package kms

import (
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/ThalesGroup/crypto11"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/public"
	"github.com/go-oidfed/lib/unixtime"
)

// NewSingleAlgPKCS11KMS constructs a PKCS#11-backed KMS for a single algorithm.
func NewSingleAlgPKCS11KMS(
	alg jwa.SignatureAlgorithm,
	config PKCS11KMSConfig, pks public.PublicKeyStorage,
) KeyManagementSystem {
	config.Algs = []jwa.SignatureAlgorithm{alg}
	config.DefaultAlg = alg
	return &PKCS11KMS{
		PKCS11KMSConfig: config,
		PKs:             pks,
	}
}

// PKCS11KMSConfig contains configuration for the PKCS#11 KMS.
// Keys are created and looked up inside the HSM using labels derived from the KID.
// If LabelPrefix is set, labels are LabelPrefix+"_"+KID; else if TypeID is set, TypeID+"_"+KID; otherwise KID.
type PKCS11KMSConfig struct {
	KMSConfig

	// TypeID is a logical namespace for this KMS (used in labels if LabelPrefix is empty)
	TypeID string

	// ModulePath is the path to the PKCS#11 module (crypto11.Config.Path)
	ModulePath string
	// TokenLabel selects the token by label (crypto11.Config.TokenLabel)
	TokenLabel string
	// TokenSerial selects the token by serial (crypto11.Config.TokenSerial)
	TokenSerial string
	// Pin is the user PIN for the token (crypto11.Config.Pin)
	Pin string

	// Optional prefix for object labels inside HSM
	LabelPrefix string

	// ExtraLabels are HSM object labels to load into this KMS even if
	// they are not present yet in the PublicKeyStorage.
	ExtraLabels []string
}

// PKCS11KMS implements KeyManagementSystem using a PKCS#11 HSM.
type PKCS11KMS struct {
	PKCS11KMSConfig

	ctx *crypto11.Context

	// signers is a map of all loaded signers, keyed by kid
	signers map[string]crypto.Signer

	PKs public.PublicKeyStorage

	// automatic rotation control
	rotationStop chan struct{}
	rotationWG   sync.WaitGroup
}

// labeledSigner wraps a crypto.Signer and carries a stable KID (e.g., HSM label).
type labeledSigner struct {
	s   crypto.Signer
	kid string
}

// Public returns the public key associated with this signer.
func (l *labeledSigner) Public() crypto.PublicKey { return l.s.Public() }

// Sign signs digest with the private key associated with this signer.
func (l *labeledSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return l.s.Sign(rand, digest, opts)
}

// KID returns the key ID associated with this signer.
func (l *labeledSigner) KID() string { return l.kid }

// keyLabel constructs the HSM object label from kid and configured prefixes.
func (kms *PKCS11KMS) keyLabel(kid string) string {
	prefix := kms.LabelPrefix
	if prefix == "" {
		prefix = kms.TypeID
	}
	if prefix == "" {
		return kid
	}
	return fmt.Sprintf("%s_%s", prefix, kid)
}

// GetDefault returns a crypto.Signer and the corresponding jwa.SignatureAlgorithm
func (kms *PKCS11KMS) GetDefault() (crypto.Signer, jwa.SignatureAlgorithm) {
	if len(kms.Algs) == 0 {
		return nil, jwa.SignatureAlgorithm{}
	}
	var algs []string
	if kms.DefaultAlg.String() != "" {
		algs = []string{kms.DefaultAlg.String()}
	}
	for _, a := range kms.Algs {
		algs = append(algs, a.String())
	}
	return kms.GetForAlgs(algs...)
}

// GetForAlgs returns a signer for the first acceptable algorithm found among active keys.
func (kms *PKCS11KMS) GetForAlgs(algs ...string) (
	crypto.Signer,
	jwa.SignatureAlgorithm,
) {
	activePKs, err := kms.PKs.GetActive()
	if err != nil {
		log.WithError(err).Error("pkcs#11 KMS: failed to get active public keys")
		return nil, jwa.SignatureAlgorithm{}
	}
	pksByAlg := activePKs.ByAlg()
	for _, alg := range kms.Algs {
		if !slices.Contains(algs, alg.String()) {
			continue
		}
		algPKs, ok := pksByAlg[alg]
		if !ok || len(algPKs) == 0 {
			continue
		}
		pk := algPKs[0]
		if len(algPKs) > 1 {
			maxExp := unixtime.Now()
			maxExpWithNbf := maxExp
			maxExpIndex := -1
			maxExpWithNbfIndex := -1
			nbfTreshold := time.Now().Add(-kms.KeyRotation.Overlap.Duration() / 2)
			for i, it := range algPKs {
				if it.NotBefore.Before(nbfTreshold) && it.ExpiresAt.After(
					maxExpWithNbf.Time,
				) {
					maxExpWithNbf = it.ExpiresAt
					maxExpWithNbfIndex = i

				} else if maxExpIndex == -1 && it.ExpiresAt.After(maxExp.Time) {
					maxExp = it.ExpiresAt
					maxExpIndex = i
				}
			}
			if maxExpWithNbfIndex != -1 {
				pk = algPKs[maxExpWithNbfIndex]
			} else {
				pk = algPKs[maxExpIndex]
			}
		}
		signer, ok := kms.signers[pk.KID]
		if !ok {
			continue
		}
		return signer, alg
	}
	return nil, jwa.SignatureAlgorithm{}
}

// Load initializes the PKCS#11 context, loads HSM-resident signers for active keys,
// and generates any missing keys if enabled.
func (kms *PKCS11KMS) Load() error {
	if kms.signers == nil {
		kms.signers = make(map[string]crypto.Signer)
	}
	if kms.ctx == nil {
		cfg := &crypto11.Config{
			Path:        kms.ModulePath,
			TokenLabel:  kms.TokenLabel,
			TokenSerial: kms.TokenSerial,
			Pin:         kms.Pin,
		}
		ctx, err := crypto11.Configure(cfg)
		if err != nil {
			return errors.Wrap(err, "pkcs11 kms: configure crypto11")
		}
		kms.ctx = ctx
	}

	activePKs, err := kms.PKs.GetActive()
	if err != nil {
		return err
	}

	loadedAlgs := make(map[jwa.SignatureAlgorithm]struct{})
	for _, activePK := range activePKs {
		kid := activePK.KID
		kalg, _ := activePK.Key.Algorithm()
		alg, ok := kalg.(jwa.SignatureAlgorithm)
		if !ok {
			continue
		}
		if !kms.algorithmSupported(alg) {
			continue
		}
		// Load signer by label (kid-derived)
		signer, err := kms.findKeyByKID(kid)
		if err != nil {
			return err
		}
		if signer == nil {
			continue
		}
		kms.signers[kid] = signer
		// Wrap with label so downstream signing can set kid header from HSM label
		kms.signers[kid] = &labeledSigner{
			s:   signer,
			kid: kid,
		}
		loadedAlgs[alg] = struct{}{}
	}

	for _, alg := range kms.Algs {
		if _, ok := loadedAlgs[alg]; ok {
			continue
		}
		// Not available; create if allowed
		if !kms.GenerateKeys {
			return errors.Errorf(
				"no existing HSM signing key for alg '%s'. Enable key generation or provision keys",
				alg,
			)
		}
		if _, err = kms.generateNewSigner(alg, nbfModeNow); err != nil {
			return err
		}
	}
	// Load extra labels explicitly requested via config
	for _, label := range kms.ExtraLabels {
		signer, ferr := kms.ctx.FindKeyPair(nil, []byte(label))
		if ferr != nil {
			log.WithError(ferr).WithField("label", label).Warn("pkcs#11 KMS: failed to find extra label")
			continue
		}
		if signer == nil {
			continue
		}
		alg, algErr := kms.algForSigner(signer)
		if algErr != nil {
			log.WithError(algErr).WithField(
				"label", label,
			).Warn("pkcs#11 KMS: could not determine algorithm for extra label")
			continue
		}
		pk, _, pkErr := jwx.SignerToPublicJWK(signer, alg)
		if pkErr != nil {
			log.WithError(pkErr).WithField(
				"label", label,
			).Warn("pkcs#11 KMS: failed to derive public JWK for extra label")
			continue
		}
		_ = pk.Set(jwk.KeyIDKey, label)
		existing, gerr := kms.PKs.Get(label)
		if gerr != nil {
			log.WithError(gerr).WithField(
				"label", label,
			).Warn("pkcs#11 KMS: failed to query public storage for extra label")
			continue
		}
		if existing == nil {
			now := unixtime.Now()
			var exp unixtime.Unixtime
			if kms.KeyRotation.Enabled {
				exp = unixtime.Unixtime{Time: now.Add(kms.KeyRotation.Interval.Duration())}
			}
			pke := public.PublicKeyEntry{
				KID:       label,
				Key:       pk,
				IssuedAt:  now,
				NotBefore: now,
				UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{
					ExpiresAt: exp,
				},
			}
			if aerr := kms.PKs.Add(pke); aerr != nil {
				log.WithError(aerr).WithField(
					"label", label,
				).Warn("pkcs#11 KMS: failed to add extra label to public storage")
				continue
			}
		}
		// Wrap with label so downstream signing can set kid header from HSM label
		kms.signers[label] = &labeledSigner{
			s:   signer,
			kid: label,
		}
	}
	return nil
}

// algorithmSupported reports whether the given algorithm is among the configured ones.
func (kms *PKCS11KMS) algorithmSupported(alg jwa.SignatureAlgorithm) bool {
	for _, a := range kms.Algs {
		if a.String() == alg.String() {
			return true
		}
	}
	return false
}

// algForSigner determines a configured jwa.SignatureAlgorithm suitable for the signer’s key type.
func (kms *PKCS11KMS) algForSigner(signer crypto.Signer) (jwa.SignatureAlgorithm, error) {
	pub := signer.Public()
	switch t := pub.(type) {
	case *rsa.PublicKey:
		for _, a := range kms.Algs {
			switch a {
			case jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512():
				return a, nil
			}
		}
		return jwa.SignatureAlgorithm{}, errors.New("no RSA algorithms configured for loaded HSM key")
	case *ecdsa.PublicKey:
		var want jwa.SignatureAlgorithm
		switch t.Curve {
		case elliptic.P256():
			want = jwa.ES256()
		case elliptic.P384():
			want = jwa.ES384()
		case elliptic.P521():
			want = jwa.ES512()
		default:
			return jwa.SignatureAlgorithm{}, errors.New("unsupported ECDSA curve")
		}
		for _, a := range kms.Algs {
			if a.String() == want.String() {
				return a, nil
			}
		}
		return jwa.SignatureAlgorithm{}, errors.Errorf("algorithm %s not configured for loaded ECDSA HSM key", want)
	case ed25519.PublicKey:
		for _, a := range kms.Algs {
			if a.String() == jwa.EdDSA().String() {
				return a, nil
			}
		}
		return jwa.SignatureAlgorithm{}, errors.New("EdDSA not configured for loaded HSM key")
	default:
		return jwa.SignatureAlgorithm{}, errors.New("unknown HSM key type")
	}
}

// findKeyByKID locates a key pair by label derived from the kid (with optional prefix).
func (kms *PKCS11KMS) findKeyByKID(kid string) (crypto.Signer, error) {
	if kms.ctx == nil {
		return nil, errors.New("pkcs11 kms: context not initialized")
	}
	// First try exact kid as label, then fallback to prefixed label to support legacy configs
	signer, err := kms.ctx.FindKeyPair(nil, []byte(kid))
	if err != nil {
		return nil, errors.Wrap(err, "pkcs11 kms: find key by label")
	}
	if signer == nil {
		signer, err = kms.ctx.FindKeyPair(nil, []byte(kms.keyLabel(kid)))
		if err != nil {
			return nil, errors.Wrap(err, "pkcs11 kms: fallback find key by prefixed label")
		}
	}
	return signer, nil
}

// generateNewSigner creates a new key pair inside the HSM for the given algorithm
// and registers its public part in PublicKeyStorage.
func (kms *PKCS11KMS) generateNewSigner(
	alg jwa.SignatureAlgorithm,
	mode nbfMode,
) (*public.PublicKeyEntry, error) {
	if kms.ctx == nil {
		return nil, errors.New("pkcs11 kms: context not initialized")
	}

	u, err := uuid.NewV7()
	if err != nil {
		return nil, errors.Wrap(err, "could not generate uuid")
	}
	kid := u.String()
	label := kms.keyLabel(kid)
	signer, err := kms.generateKeyInHSM(alg, kid, label)
	if err != nil {
		return nil, err
	}

	pk, _, err := jwx.SignerToPublicJWK(signer, alg)
	if err != nil {
		return nil, err
	}
	// Override the kid to match the HSM label
	_ = pk.Set(jwk.KeyIDKey, label)

	now := unixtime.Now()
	var nbf unixtime.Unixtime
	switch mode {
	case nbfModeNow:
		nbf = now
	case nbfModeNext:
		lifetime, err := kms.KeyRotation.EntityConfigurationLifetimeFunc()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get entity configuration lifetime")
		}
		nbf = unixtime.Unixtime{Time: now.Add(lifetime)}
	default:
		return nil, errors.New("invalid nbf mode")
	}
	var exp unixtime.Unixtime
	if kms.KeyRotation.Enabled {
		exp = unixtime.Unixtime{Time: nbf.Add(kms.KeyRotation.Interval.Duration())}
	}
	pke := public.PublicKeyEntry{
		KID:       label,
		Key:       pk,
		IssuedAt:  now,
		NotBefore: nbf,
		UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{
			ExpiresAt: exp,
		},
	}
	if err = kms.PKs.Add(pke); err != nil {
		return nil, err
	}
	// Wrap with label so downstream signing can set kid header from HSM label
	kms.signers[label] = &labeledSigner{
		s:   signer,
		kid: label,
	}
	return &pke, nil
}

func (kms *PKCS11KMS) generateKeyInHSM(alg jwa.SignatureAlgorithm, kid, label string) (crypto.Signer, error) {
	var signer crypto.Signer
	var err error
	switch alg {
	case jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512():
		signer, err = kms.ctx.GenerateRSAKeyPairWithLabel([]byte(kid), []byte(label), kms.RSAKeyLen)
	case jwa.ES256():
		signer, err = kms.ctx.GenerateECDSAKeyPairWithLabel([]byte(kid), []byte(label), elliptic.P256())
	case jwa.ES384():
		signer, err = kms.ctx.GenerateECDSAKeyPairWithLabel([]byte(kid), []byte(label), elliptic.P384())
	case jwa.ES512():
		signer, err = kms.ctx.GenerateECDSAKeyPairWithLabel([]byte(kid), []byte(label), elliptic.P521())
	default:
		return nil, errors.New("unknown signing algorithm: " + alg.String())
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return signer, nil
}

// Rotation functions mirror FilesystemKMS logic, operating purely on public key metadata
// and leveraging HSM-backed key generation.
func (kms *PKCS11KMS) rotateKeys(kids []string, revoked bool, reason string) error {
	log.WithFields(
		log.Fields{
			"kids":    kids,
			"revoked": revoked,
		},
	).Info("pkcs#11 KMS: rotation: start")
	ks := make([]*public.PublicKeyEntry, len(kids))
	var signingAlg jwa.SignatureAlgorithm
	latestExp := time.Time{}
	for i, kid := range kids {
		k, err := kms.PKs.Get(kid)
		if err != nil {
			return err
		}
		alg, _ := k.Key.Algorithm()
		if signingAlg.String() == "" {
			signingAlg = alg.(jwa.SignatureAlgorithm)
		} else {
			if signingAlg.String() != alg.String() {
				return errors.New("all keys must be of the same algorithm")
			}
		}
		ks[i] = k
		if !k.ExpiresAt.IsZero() && (latestExp.IsZero() || k.ExpiresAt.After(latestExp)) {
			latestExp = k.ExpiresAt.Time
		}
	}
	mode := nbfModeNext
	if revoked {
		mode = nbfModeNow
	}
	// Avoid gaps: if the computed future NotBefore would be after latest current expiration,
	// activate the new key immediately.
	if mode == nbfModeNext {
		if lifetime, err := kms.KeyRotation.EntityConfigurationLifetimeFunc(); err == nil {
			if time.Now().Add(lifetime).After(latestExp) {
				mode = nbfModeNow
			}
		}
	}
	pk, err := kms.generateNewSigner(signingAlg, mode)
	if err != nil {
		return err
	}
	log.WithFields(
		log.Fields{
			"alg":     signingAlg.String(),
			"mode":    fmt.Sprintf("%v", mode),
			"new_kid": pk.KID,
		},
	).Info("pkcs#11 KMS: rotation: generated new key")
	newExpForOldKey := unixtime.Unixtime{Time: pk.NotBefore.Add(kms.KeyRotation.Overlap.Duration())}
	for _, k := range ks {
		if revoked {
			k.RevokedAt = unixtime.Now()
			k.Reason = reason
		}
		// Ensure continuous coverage by setting old expiration to new.nbf + overlap
		if k.ExpiresAt.IsZero() || newExpForOldKey.Before(k.ExpiresAt.Time) || newExpForOldKey.After(k.ExpiresAt.Time) {
			k.ExpiresAt = newExpForOldKey
		}
		if err = kms.PKs.Update(k.KID, k.UpdateablePublicKeyMetadata); err != nil {
			return err
		}
	}
	log.WithFields(
		log.Fields{
			"alg":     signingAlg.String(),
			"new_kid": pk.KID,
		},
	).Info("pkcs#11 KMS: rotation: completed")
	return nil
}

func (kms *PKCS11KMS) RotateKey(kid string, revoked bool, reason string) error {
	log.WithFields(
		log.Fields{
			"kid":     kid,
			"revoked": revoked,
		},
	).Info("pkcs#11 KMS: rotate key")
	return kms.rotateKeys([]string{kid}, revoked, reason)
}

// RotateAllKeys rotates all active keys per configured algorithm, optionally revoking them.
func (kms *PKCS11KMS) RotateAllKeys(revoked bool, reason string) error {
	activePKs, err := kms.PKs.GetActive()
	if err != nil {
		return err
	}
	pksByAlg := activePKs.ByAlg()
	for _, alg := range kms.Algs {
		algPKs, ok := pksByAlg[alg]
		if !ok || len(algPKs) == 0 {
			if _, err = kms.generateNewSigner(alg, nbfModeNow); err != nil {
				return err
			}
			log.WithField("alg", alg.String()).Info("pkcs#11 KMS: rotation: seeded new key for alg with no active keys")
		}
		kids := make([]string, len(algPKs))
		for i, pk := range algPKs {
			kids[i] = pk.KID
		}
		log.WithField("alg", alg.String()).Info("pkcs#11 KMS: rotation: processing alg")
		if err = kms.rotateKeys(kids, revoked, reason); err != nil {
			return err
		}
	}
	return nil
}

// StartAutomaticRotation launches a background loop to rotate keys ahead of expiration.
func (kms *PKCS11KMS) StartAutomaticRotation() error {
	if !kms.KeyRotation.Enabled {
		return nil
	}
	// ensure only one rotation loop runs
	if kms.rotationStop != nil {
		return nil
	}
	log.Info("pkcs#11 KMS: automatic rotation: starting")
	kms.rotationStop = make(chan struct{})
	kms.rotationWG.Add(1)
	go func() {
		defer kms.rotationWG.Done()
		for {
			nextSleep, didRotate := kms.rotationStep(time.Now())
			// If we rotated, loop again immediately unless asked to stop.
			if didRotate {
				select {
				case <-kms.rotationStop:
					return
				default:
				}
				continue
			}
			// Sleep until the next threshold or future key activation.
			if nextSleep <= 0 {
				nextSleep = time.Second
			}
			timer := time.NewTimer(nextSleep)
			select {
			case <-kms.rotationStop:
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
				// loop
			}
		}
	}()
	return nil
}

// rotationStep performs one evaluation/rotation cycle and returns the next sleep
// interval and whether any rotation or seeding occurred (didRotate).
func (kms *PKCS11KMS) rotationStep(now time.Time) (time.Duration, bool) {
	// default sleep if we cannot compute anything meaningful
	nextSleep := kms.KeyRotation.Overlap.Duration() / 2
	// clamp to a minimum to avoid busy loops when overlap is zero
	const minSleep = time.Second
	if nextSleep <= 0 {
		nextSleep = minSleep
	}
	didRotate := false

	activePKs, err := kms.PKs.GetActive()
	if err != nil {
		log.WithError(err).Error("pkcs#11 KMS: automatic rotation: failed to get active public keys")
		return nextSleep, false
	}
	pksByAlg := activePKs.ByAlg()
	// iterate only configured algorithms
	for _, alg := range kms.Algs {
		sleepCandidate, rotated := kms.rotationEvaluationForAlg(pksByAlg, alg, now, minSleep)
		if rotated {
			didRotate = true
		}
		if sleepCandidate > 0 && sleepCandidate < nextSleep {
			nextSleep = sleepCandidate
		}
	}

	return nextSleep, didRotate
}

// rotationEvaluationForAlg evaluates rotation needs for a single algorithm.
// It returns a candidate sleep duration until the next action point and whether
// any rotation or seeding occurred.
func (kms *PKCS11KMS) rotationEvaluationForAlg(
	pksByAlg map[jwa.SignatureAlgorithm]public.PublicKeyEntryList,
	alg jwa.SignatureAlgorithm,
	now time.Time,
	minSleep time.Duration,
) (time.Duration, bool) {
	algPKs, ok := pksByAlg[alg]
	if !ok || len(algPKs) == 0 {
		// No active keys: before seeding, check if a valid future key already exists.
		earliestNbf, hasFuture, vErr := earliestFutureNbfForAlg(kms.PKs, alg, now)
		if vErr != nil {
			log.WithError(vErr).Error("pkcs#11 KMS: automatic rotation: failed to get valid public keys for future check")
			return 0, false
		}
		if hasFuture {
			// sleep until future key becomes active
			wait := time.Until(earliestNbf)
			if wait < minSleep {
				wait = minSleep
			}
			return wait, false
		}
		// no active and no future key; seed immediately
		if _, err := kms.generateNewSigner(alg, nbfModeNow); err != nil {
			log.WithError(err).Error("pkcs#11 KMS: automatic rotation: failed to seed key for alg")
			// ensure we don't spin; retry soon-ish
			return minSleep, false
		}
		// re-evaluate immediately to include the new key in active set
		return 0, true
	}

	// pick the key with latest expiration as the current signer for this alg
	current := slices.MaxFunc(
		algPKs, func(a, b public.PublicKeyEntry) int {
			return cmp.Compare(a.ExpiresAt.Unix(), b.ExpiresAt.Unix())
		},
	)

	// Trigger early enough to accommodate nbf = now + lifetime
	lifetime := time.Duration(0)
	if kms.KeyRotation.EntityConfigurationLifetimeFunc != nil {
		if lt, lerr := kms.KeyRotation.EntityConfigurationLifetimeFunc(); lerr == nil {
			lifetime = lt
		} else {
			log.WithError(lerr).Warn("pkcs#11 KMS: automatic rotation: failed to get lifetime; using 0")
		}
	}
	threshold := current.ExpiresAt.Time.Add(-kms.KeyRotation.Overlap.Duration()).Add(-lifetime)
	if !threshold.After(now) {
		kids := make([]string, len(algPKs))
		for i, pk := range algPKs {
			kids[i] = pk.KID
		}
		// If there is already a future key, do not generate another; only shorten old exp
		if earliestNbf, hasFuture, vErr := earliestFutureNbfForAlg(kms.PKs, alg, now); vErr == nil && hasFuture {
			shortenExpirationUntilFuture(kms.PKs, algPKs, earliestNbf, kms.KeyRotation.Overlap.Duration(), "pkcs#11 KMS")
			wait := time.Until(earliestNbf)
			if wait < minSleep {
				wait = minSleep
			}
			return wait, false
		}
		if err := kms.rotateKeys(kids, false, ""); err != nil {
			log.WithError(err).Error("pkcs#11 KMS: automatic rotation: rotate failed")
			return minSleep, false
		}
		return 0, true
	}
	// schedule rotation when threshold is reached
	wait := time.Until(threshold)
	if wait < minSleep {
		wait = minSleep
	}
	return wait, false
}

// earliestFutureNbfForAlg returns the earliest NotBefore among valid, non-revoked
// keys for the given algorithm, that are in the future relative to now.
// Removed local earliestFutureNbfForAlg and shortenExpirationUntilFuture in favor of shared helpers.

// StopAutomaticRotation stops the background rotation loop.
func (kms *PKCS11KMS) StopAutomaticRotation() {
	if kms.rotationStop == nil {
		return
	}
	close(kms.rotationStop)
	kms.rotationWG.Wait()
	log.Info("pkcs#11 KMS: automatic rotation: stopped")
	kms.rotationStop = nil
}
