package kms

import (
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/pkg/errors"
	"github.com/zachmann/go-utils/sliceutils"

	log "github.com/go-oidfed/lib/internal"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/public"
	"github.com/go-oidfed/lib/unixtime"
)

// PEMStorageKMS implements KeyManagementSystem using PEM-encoded private keys
// with pluggable storage backends via PEMStorer and KMSStateStorer interfaces.
type PEMStorageKMS struct {
	KMSConfig

	pemStorer   PEMStorer
	stateStorer KMSStateStorer

	// signers is a map of all loaded signers, where the key is the kid
	signers map[string]crypto.Signer

	PKs public.PublicKeyStorage

	// automatic rotation control
	rotationStop chan struct{}
	rotationWG   sync.WaitGroup
}

// NewPEMStorageKMS creates a new PEMStorageKMS with the given storage backends.
// The caller must call Load() to initialize the key storage.
func NewPEMStorageKMS(
	config KMSConfig,
	pemStorer PEMStorer,
	stateStorer KMSStateStorer,
	pks public.PublicKeyStorage,
) *PEMStorageKMS {
	return &PEMStorageKMS{
		KMSConfig:   config,
		pemStorer:   pemStorer,
		stateStorer: stateStorer,
		PKs:         pks,
		signers:     make(map[string]crypto.Signer),
	}
}

// GetPendingChanges returns the pending alg and default change, if any.
func (kms *PEMStorageKMS) GetPendingChanges() (*PendingAlgChange, *PendingDefaultChange) {
	loadedState, err := kms.loadScheduledState()
	if err != nil {
		log.WithError(err).Error("PEMStorageKMS: failed to load scheduled state")
		return nil, nil
	}
	return loadedState.PendingAlgChange, loadedState.PendingDefaultChange
}

// GetDefaultAlg returns the default algorithm
func (kms *PEMStorageKMS) GetDefaultAlg() jwa.SignatureAlgorithm {
	return kms.DefaultAlg
}

// GetAlgs returns the configured algorithms
func (kms *PEMStorageKMS) GetAlgs() []jwa.SignatureAlgorithm {
	return kms.Algs
}

func (kms *PEMStorageKMS) loadScheduledState() (ScheduledState, error) {
	return kms.stateStorer.LoadScheduledState()
}

func (kms *PEMStorageKMS) saveScheduledState(st ScheduledState) error {
	return kms.stateStorer.SaveScheduledState(st)
}

// ChangeAlgs updates the set of configured signature algorithms.
// It stops automatic rotation (if running), replaces the algorithms,
// reloads/generates keys as needed via Load, and restarts rotation
// if rotation is enabled. No-op when the set is unchanged.
func (kms *PEMStorageKMS) ChangeAlgs(algs []jwa.SignatureAlgorithm) error {
	if slices.Equal(kms.Algs, algs) {
		return nil
	}
	if !kms.GenerateKeys {
		return errors.New("changing algorithms dynamically (without a restart) is not supported when key generation is disabled")
	}
	kms.StopAutomaticRotation()
	kms.Algs = algs
	if err := kms.Load(); err != nil {
		return err
	}
	if kms.KeyRotation.Enabled {
		return kms.StartAutomaticRotation()
	}
	return nil
}

// ChangeGenerateKeys toggles whether the KMS is allowed to generate
// missing private keys for the configured algorithms. When enabling,
// it immediately calls Load to create any missing keys.
func (kms *PEMStorageKMS) ChangeGenerateKeys(generate bool) error {
	if kms.GenerateKeys == generate {
		return nil
	}
	kms.GenerateKeys = generate
	if generate {
		return kms.Load()
	}
	return nil
}

// ChangeRSAKeyLength sets the RSA key length to be used for
// future key generation. Existing keys are unaffected.
func (kms *PEMStorageKMS) ChangeRSAKeyLength(length int) error {
	if kms.RSAKeyLen == length {
		return nil
	}
	kms.RSAKeyLen = length
	return nil
}

// ChangeDefaultAlgorithm sets the default algorithm used when
// selecting a signer without an explicit alg preference. The
// algorithm must be part of the configured set.
func (kms *PEMStorageKMS) ChangeDefaultAlgorithm(alg jwa.SignatureAlgorithm) error {
	if kms.DefaultAlg.String() == alg.String() {
		return nil
	}
	if !slices.ContainsFunc(
		kms.Algs,
		func(a jwa.SignatureAlgorithm) bool { return a.String() == alg.String() },
	) {
		return errors.Errorf("algorithm '%s' not in configured algs '%v'", alg, kms.Algs)
	}
	kms.DefaultAlg = alg
	return nil
}

// ChangeDefaultAlgorithmAt schedules a change of the default algorithm at a
// specific time. Before the switch, it ensures a future-dated key for the
// target algorithm exists (nbf >= effectiveAt).
func (kms *PEMStorageKMS) ChangeDefaultAlgorithmAt(alg jwa.SignatureAlgorithm, effectiveAt unixtime.Unixtime) error {
	if alg.String() == "" {
		return errors.New("invalid algorithm")
	}
	st, err := kms.loadScheduledState()
	if err != nil {
		return err
	}
	if st.PendingDefaultChange != nil &&
		st.PendingDefaultChange.Alg.String() == alg.String() &&
		st.PendingDefaultChange.EffectiveAt.Equal(effectiveAt.Time) {
		return nil
	}
	if kms.DefaultAlg.String() == alg.String() {
		if st.PendingDefaultChange == nil || (st.PendingDefaultChange != nil &&
			st.PendingDefaultChange.Alg.String() == alg.String() &&
			st.PendingDefaultChange.EffectiveAt.Equal(effectiveAt.Time)) {
			return nil
		}
	}
	if !kms.GenerateKeys {
		return errors.New("scheduling default algorithm change requires key generation to be enabled")
	}
	if err = kms.ensureFutureKey(alg, effectiveAt.Time); err != nil {
		return err
	}
	st.PendingDefaultChange = &PendingDefaultChange{
		Alg:         alg,
		EffectiveAt: effectiveAt,
	}
	if err = kms.saveScheduledState(st); err != nil {
		return err
	}
	return nil
}

// ChangeKeyRotationConfig updates the automatic rotation settings.
// If effective values change, it stops any existing rotation loop
// and (re)starts it based on the new configuration.
func (kms *PEMStorageKMS) ChangeKeyRotationConfig(config KeyRotationConfig) error {
	prev := kms.KeyRotation
	kms.KeyRotation = config
	same := prev.Enabled == config.Enabled &&
		prev.Interval.Duration() == config.Interval.Duration() &&
		prev.Overlap.Duration() == config.Overlap.Duration() &&
		prev.KeyAnnouncementLeadTime.Duration() == config.KeyAnnouncementLeadTime.Duration() &&
		prev.KeyAnnouncementLeadTimeECMultiplier == config.KeyAnnouncementLeadTimeECMultiplier
	if same {
		return nil
	}
	if prev.Enabled {
		kms.StopAutomaticRotation()
	}
	if config.Enabled {
		return kms.StartAutomaticRotation()
	}
	return nil
}

// GetDefault returns a crypto.Signer and the corresponding jwa.SignatureAlgorithm
func (kms *PEMStorageKMS) GetDefault() (crypto.Signer, jwa.SignatureAlgorithm) {
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

// GetForAlgs takes a list of acceptable signature algorithms and returns a
// usable crypto.Signer or nil as well as the corresponding
// jwa.SignatureAlgorithm
func (kms *PEMStorageKMS) GetForAlgs(algs ...string) (
	crypto.Signer,
	jwa.SignatureAlgorithm,
) {
	activePKs, err := kms.PKs.GetActive()
	if err != nil {
		log.WithError(err).Error("PEMStorageKMS: failed to get active public keys")
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
		sortedIndices := sortKeysByPreference(algPKs, kms.KeyRotation.Overlap.Duration())
		for _, idx := range sortedIndices {
			pk := algPKs[idx]
			signer, ok := kms.signers[pk.KID]
			if !ok {
				log.WithFields(log.Fields{
					"kid": pk.KID,
					"alg": alg.String(),
				}).Debug("PEMStorageKMS: skipping public key without matching private key")
				continue
			}
			return signer, alg
		}
		log.WithField("alg", alg.String()).Debug(
			"PEMStorageKMS: no usable key pair found for algorithm",
		)
	}
	return nil, jwa.SignatureAlgorithm{}
}

// Load loads the private keys from storage and generates missing keys when
// configured to do so.
func (kms *PEMStorageKMS) Load() error {
	log.Debugf("PEMStorageKMS: loading keys")
	if kms.signers == nil {
		kms.signers = make(map[string]crypto.Signer)
	}

	log.Debug("PEMStorageKMS: loading active pks")
	activePKs, err := kms.PKs.GetActive()
	if err != nil {
		return err
	}
	log.Debugf("PEMStorageKMS: found %d active keys in pk storage", len(activePKs))
	var loadedAlgs map[jwa.SignatureAlgorithm]struct{}
	loadedAlgs = make(map[jwa.SignatureAlgorithm]struct{})
	for _, activePK := range activePKs {
		kid := activePK.KID
		kalg, _ := activePK.Key.Algorithm()
		alg := kalg.(jwa.SignatureAlgorithm)
		signer, err := kms.readSigner(kid, alg)
		if err != nil {
			log.WithError(err).WithField("kid", kid).Warn("PEMStorageKMS: could not load signing key")
		} else {
			kms.signers[kid] = signer
			loadedAlgs[alg] = struct{}{}
		}
	}
	log.Debugf("PEMStorageKMS: loaded %d active keys", len(kms.signers))

	log.Debug("PEMStorageKMS: Checking that all signing algs have a valid key")
	for _, alg := range kms.Algs {
		if _, ok := loadedAlgs[alg]; ok {
			log.WithField("alg", alg.String()).Debug("PEMStorageKMS: key for alg already found")
			continue
		}
		log.WithField("alg", alg.String()).Debug("PEMStorageKMS: key for alg is missing")
		if !kms.GenerateKeys {
			log.Info("PEMStorageKMS: key generation disabled")
			return errors.Errorf(
				"no existing signing key for alg '%s'. Assure the file exists and has the correct format or enable key generation.",
				alg,
			)
		}
		log.Info("PEMStorageKMS: generating new signing key")
		if _, err = kms.generateNewSigner(alg, nbfModeNow); err != nil {
			return err
		}
	}
	return nil
}

func (kms *PEMStorageKMS) readSigner(kid string, alg jwa.SignatureAlgorithm) (crypto.Signer, error) {
	pemData, err := kms.pemStorer.ReadPEM(kid)
	if err != nil {
		return nil, err
	}
	return readSignerFromPEM(pemData, alg)
}

func (kms *PEMStorageKMS) writeSigner(kid string, sk crypto.Signer) error {
	pemData, err := writeSignerToPEM(sk)
	if err != nil {
		return err
	}
	return kms.pemStorer.WritePEM(kid, pemData)
}

func writeSignerToPEM(sk crypto.Signer) ([]byte, error) {
	switch sk := sk.(type) {
	case *rsa.PrivateKey:
		return exportRSAPrivateKeyAsPEM(sk)
	case *ecdsa.PrivateKey:
		return exportECPrivateKeyAsPEM(sk)
	case ed25519.PrivateKey:
		return exportEDDSAPrivateKeyAsPEM(sk)
	default:
		return nil, errors.New("unsupported key type")
	}
}

func (kms *PEMStorageKMS) generateNewSigner(
	alg jwa.SignatureAlgorithm,
	mode nbfMode,
) (*public.PublicKeyEntry, error) {
	sk, pk, kid, err := jwx.GenerateKeyPair(alg, kms.RSAKeyLen)
	if err != nil {
		return nil, err
	}
	now := unixtime.Now()
	var nbf *unixtime.Unixtime
	switch mode {
	case nbfModeNow:
		nbf = &now
	case nbfModeNext:
		leadTime, err := kms.KeyRotation.KeyAnnouncementLeadTimeDuration()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get key announcement lead time")
		}
		nbf = &unixtime.Unixtime{Time: now.Add(leadTime)}
	case nbfModeAt:
		return nil, errors.New("nbfModeAt requires explicit time; use generateNewSignerAt")
	default:
		return nil, errors.New("invalid nbf mode")
	}
	var exp *unixtime.Unixtime
	if kms.KeyRotation.Enabled {
		exp = &unixtime.Unixtime{Time: nbf.Add(kms.KeyRotation.Interval.Duration())}
	}
	pke := public.PublicKeyEntry{
		KID:       kid,
		Key:       public.JWKKey{Key: pk},
		IssuedAt:  &now,
		NotBefore: nbf,
		UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{
			ExpiresAt: exp,
		},
	}
	if err = kms.PKs.Add(pke); err != nil {
		return nil, err
	}
	if err = kms.writeSigner(kid, sk); err != nil {
		return nil, err
	}
	kms.signers[kid] = sk
	return &pke, nil
}

func (kms *PEMStorageKMS) generateNewSignerAt(
	alg jwa.SignatureAlgorithm,
	nbfAt time.Time,
) (*public.PublicKeyEntry, error) {
	sk, pk, kid, err := jwx.GenerateKeyPair(alg, kms.RSAKeyLen)
	if err != nil {
		return nil, err
	}
	now := unixtime.Now()
	nbf := &unixtime.Unixtime{Time: nbfAt}
	var exp *unixtime.Unixtime
	if kms.KeyRotation.Enabled {
		exp = &unixtime.Unixtime{Time: nbf.Add(kms.KeyRotation.Interval.Duration())}
	}
	pke := public.PublicKeyEntry{
		KID:       kid,
		Key:       public.JWKKey{Key: pk},
		IssuedAt:  &now,
		NotBefore: nbf,
		UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{
			ExpiresAt: exp,
		},
	}
	if err = kms.PKs.Add(pke); err != nil {
		return nil, err
	}
	if err = kms.writeSigner(kid, sk); err != nil {
		return nil, err
	}
	kms.signers[kid] = sk
	return &pke, nil
}

func (kms *PEMStorageKMS) ensureFutureKey(alg jwa.SignatureAlgorithm, effectiveAt time.Time) error {
	valid, err := kms.PKs.GetValid()
	if err != nil {
		return err
	}
	for _, pk := range valid {
		a, _ := pk.Key.Algorithm()
		if as, ok := a.(jwa.SignatureAlgorithm); ok && as.String() == alg.String() {
			if pk.RevokedAt != nil && !pk.RevokedAt.IsZero() && pk.RevokedAt.Before(time.Now()) {
				continue
			}
			if pk.NotBefore != nil && !pk.NotBefore.IsZero() && !pk.NotBefore.Before(effectiveAt) {
				return nil
			}
		}
	}
	_, err = kms.generateNewSignerAt(alg, effectiveAt)
	return err
}

// ChangeAlgsAt schedules a change of the algorithm set at a specific time.
// It pre-generates future-dated keys for the new algorithms and shortens the
// expiration of old algorithms to effectiveAt + overlap.
func (kms *PEMStorageKMS) ChangeAlgsAt(
	algs []jwa.SignatureAlgorithm, effectiveAt unixtime.Unixtime, overlap time.Duration,
) error {
	if len(algs) == 0 {
		return errors.New("algs must not be empty")
	}
	st, err := kms.loadScheduledState()
	if err != nil {
		return err
	}

	algEqual := sliceutils.EqualSetsFunc(
		algs, kms.Algs, func(algorithm jwa.SignatureAlgorithm) string {
			return algorithm.String()
		},
	)
	evalPendingAlgEqual := func() bool {
		return sliceutils.EqualSetsFunc(
			algs, st.PendingAlgChange.Algs,
			func(algorithm jwa.SignatureAlgorithm) string {
				return algorithm.String()
			},
		)
	}

	if st.PendingAlgChange != nil &&
		evalPendingAlgEqual() &&
		st.PendingAlgChange.EffectiveAt.Equal(effectiveAt.Time) &&
		st.PendingAlgChange.Overlap.Duration == overlap {
		return nil
	}
	if algEqual {
		if st.PendingAlgChange == nil || (st.PendingAlgChange != nil &&
			evalPendingAlgEqual() &&
			st.PendingAlgChange.EffectiveAt.Equal(effectiveAt.Time) &&
			st.PendingAlgChange.Overlap.Duration == overlap) {
			return nil
		}
	}

	if !kms.GenerateKeys {
		return errors.New("scheduling alg changes requires key generation to be enabled")
	}
	for _, alg := range algs {
		if err := kms.ensureFutureKey(alg, effectiveAt.Time); err != nil {
			return err
		}
	}
	active, err := kms.PKs.GetActive()
	if err != nil {
		return err
	}
	newSet := make(map[string]struct{})
	for _, a := range algs {
		newSet[a.String()] = struct{}{}
	}
	targetExp := &unixtime.Unixtime{Time: effectiveAt.Add(overlap)}
	byAlg := active.ByAlg()
	for alg, list := range byAlg {
		if _, ok := newSet[alg.String()]; ok {
			continue
		}
		for _, k := range list {
			if k.ExpiresAt == nil || k.ExpiresAt.IsZero() || targetExp.Before(k.ExpiresAt.Time) {
				k.ExpiresAt = targetExp
				if err = kms.PKs.Update(k.KID, k.UpdateablePublicKeyMetadata); err != nil {
					log.WithError(err).Error("PEMStorageKMS: schedule algs: failed to update old key exp")
				}
			}
		}
	}
	st.PendingAlgChange = &PendingAlgChange{
		Algs:        algs,
		EffectiveAt: effectiveAt,
		Overlap:     unixtime.DurationInSeconds{Duration: overlap},
	}
	if err = kms.saveScheduledState(st); err != nil {
		return err
	}
	return nil
}

func (kms *PEMStorageKMS) rotateKeys(kids []string, revoked bool, reason string) error {
	log.WithFields(
		log.Fields{
			"kids":    kids,
			"revoked": revoked,
		},
	).Info("PEMStorageKMS: rotation: start")
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
		if k.ExpiresAt != nil && !k.ExpiresAt.IsZero() && (latestExp.IsZero() || k.ExpiresAt.After(latestExp)) {
			latestExp = k.ExpiresAt.Time
		}
	}
	mode := nbfModeNext
	if revoked {
		mode = nbfModeNow
	}
	if mode == nbfModeNext {
		if leadTime, err := kms.KeyRotation.KeyAnnouncementLeadTimeDuration(); err == nil {
			if time.Now().Add(leadTime).After(latestExp) {
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
	).Info("PEMStorageKMS: rotation: generated new key")
	newExpForOldKey := &unixtime.Unixtime{Time: pk.NotBefore.Add(kms.KeyRotation.Overlap.Duration())}
	for _, k := range ks {
		if revoked {
			now := unixtime.Now()
			k.RevokedAt = &now
			k.Reason = reason
		}
		if k.ExpiresAt == nil || k.ExpiresAt.IsZero() || newExpForOldKey.Before(k.ExpiresAt.Time) {
			k.ExpiresAt = newExpForOldKey
		}
		if err = kms.PKs.Update(k.KID, k.UpdateablePublicKeyMetadata); err != nil {
			log.WithError(err).Error("PEMStorageKMS: rotation: failed to update key")
		}
	}
	log.WithFields(
		log.Fields{
			"alg":     signingAlg.String(),
			"new_kid": pk.KID,
		},
	).Info("PEMStorageKMS: rotation: completed")
	return nil
}

// RotateKey rotates a single key, optionally marking it revoked and recording a reason.
func (kms *PEMStorageKMS) RotateKey(kid string, revoked bool, reason string) error {
	log.WithFields(
		log.Fields{
			"kid":     kid,
			"revoked": revoked,
		},
	).Info("PEMStorageKMS: rotate key")
	return kms.rotateKeys([]string{kid}, revoked, reason)
}

// RotateAllKeys rotates all active keys per configured algorithm, optionally
// marking them revoked and recording a reason.
func (kms *PEMStorageKMS) RotateAllKeys(revoked bool, reason string) error {
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
			log.WithField(
				"alg", alg.String(),
			).Info("PEMStorageKMS: rotation: seeded new key for alg with no active keys")
		}

		kids := make([]string, len(algPKs))
		for i, pk := range algPKs {
			kids[i] = pk.KID
		}
		log.WithField("alg", alg.String()).Info("PEMStorageKMS: rotation: processing alg")
		if err = kms.rotateKeys(kids, revoked, reason); err != nil {
			return err
		}
	}
	return nil
}

// StartAutomaticRotation starts a background loop that monitors key expiration
// thresholds and rotates keys ahead of time based on the configured overlap.
func (kms *PEMStorageKMS) StartAutomaticRotation() error {
	if !kms.KeyRotation.Enabled {
		return nil
	}
	if kms.rotationStop != nil {
		return nil
	}
	log.Info("PEMStorageKMS: automatic rotation: starting")
	kms.rotationStop = make(chan struct{})
	kms.rotationWG.Add(1)
	go func() {
		defer kms.rotationWG.Done()
		for {
			nextSleep, didRotate := kms.rotationStep(time.Now())
			if didRotate {
				select {
				case <-kms.rotationStop:
				default:
				}
				continue
			}
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
			}
		}
	}()
	return nil
}

// rotationStep performs one evaluation/rotation cycle and returns the next sleep
// interval and whether any rotation or seeding occurred (didRotate).
func (kms *PEMStorageKMS) rotationStep(now time.Time) (time.Duration, bool) {
	const minSleep = time.Second
	nextSleep := max(kms.KeyRotation.Overlap.Duration()/2, minSleep)
	didRotate := false

	activePKs, err := kms.PKs.GetActive()
	if err != nil {
		log.WithError(err).Error("PEMStorageKMS: automatic rotation: failed to get active public keys")
		return nextSleep, false
	}
	pksByAlg := activePKs.ByAlg()
	for _, alg := range kms.Algs {
		sleepCandidate, rotated := kms.rotationEvaluationForAlg(pksByAlg, alg, now, minSleep)
		if rotated {
			didRotate = true
		}
		if sleepCandidate > 0 && sleepCandidate < nextSleep {
			nextSleep = sleepCandidate
		}
	}
	if st, err := kms.loadScheduledState(); err == nil {
		applyAlg := func(p *PendingAlgChange) bool {
			if p == nil {
				return false
			}
			if !now.Before(p.EffectiveAt.Time) {
				kms.Algs = p.Algs
				if err := kms.Load(); err != nil {
					log.WithError(err).Error("PEMStorageKMS: scheduled alg change: load failed")
				}
				st.PendingAlgChange = nil
				if err := kms.saveScheduledState(st); err != nil {
					log.WithError(err).Error("PEMStorageKMS: scheduled alg change: save state failed")
				}
				return true
			}
			wait := time.Until(p.EffectiveAt.Time)
			if wait > 0 && wait < nextSleep {
				nextSleep = wait
			}
			return false
		}
		applyDef := func(p *PendingDefaultChange) bool {
			if p == nil {
				return false
			}
			if !now.Before(p.EffectiveAt.Time) {
				kms.DefaultAlg = p.Alg
				st.PendingDefaultChange = nil
				if err = kms.saveScheduledState(st); err != nil {
					log.WithError(err).Error("PEMStorageKMS: scheduled default change: save state failed")
				}
				return true
			}
			wait := time.Until(p.EffectiveAt.Time)
			if wait > 0 && wait < nextSleep {
				nextSleep = wait
			}
			return false
		}
		if applyAlg(st.PendingAlgChange) {
			didRotate = true
		}
		if applyDef(st.PendingDefaultChange) {
			didRotate = true
		}
	} else {
		log.WithError(err).Error("PEMStorageKMS: scheduled state load failed")
	}
	return nextSleep, didRotate
}

// rotationEvaluationForAlg evaluates rotation needs for a single algorithm.
// It returns a candidate sleep duration until the next action point and whether
// any rotation or seeding occurred.
func (kms *PEMStorageKMS) rotationEvaluationForAlg(
	pksByAlg map[jwa.SignatureAlgorithm]public.PublicKeyEntryList,
	alg jwa.SignatureAlgorithm,
	now time.Time,
	minSleep time.Duration,
) (time.Duration, bool) {
	algPKs, ok := pksByAlg[alg]
	if !ok || len(algPKs) == 0 {
		earliestNbf, hasFuture, vErr := earliestFutureNbfForAlg(kms.PKs, alg, now)
		if vErr != nil {
			log.WithError(vErr).Error("PEMStorageKMS: automatic rotation: failed to get valid public keys for future check")
			return 0, false
		}
		if hasFuture {
			wait := time.Until(earliestNbf)
			if wait < minSleep {
				wait = minSleep
			}
			return wait, false
		}
		if _, err := kms.generateNewSigner(alg, nbfModeNow); err != nil {
			log.WithError(err).Error("PEMStorageKMS: automatic rotation: failed to seed key for alg")
			return minSleep, false
		}
		log.WithField("alg", alg.String()).Info("PEMStorageKMS: automatic rotation: seeded new key for alg")
		return 0, true
	}

	current := slices.MaxFunc(
		algPKs, func(a, b public.PublicKeyEntry) int {
			var au, bu int64
			if a.ExpiresAt != nil {
				au = a.ExpiresAt.UnixNano()
			} else {
				au = 0
			}
			if b.ExpiresAt != nil {
				bu = b.ExpiresAt.UnixNano()
			} else {
				bu = 0
			}
			return cmp.Compare(au, bu)
		},
	)

	lifetime := time.Duration(0)
	if kms.KeyRotation.EntityConfigurationLifetimeFunc != nil {
		if lt, lerr := kms.KeyRotation.EntityConfigurationLifetimeFunc(); lerr == nil {
			lifetime = lt
		} else {
			log.WithError(lerr).Warn("PEMStorageKMS: automatic rotation: failed to get lifetime; using 0")
		}
	}
	leadTime, lerr := kms.KeyRotation.KeyAnnouncementLeadTimeDuration()
	if lerr != nil {
		log.WithError(lerr).Warn("PEMStorageKMS: automatic rotation: failed to get key announcement lead time; using EC lifetime")
		leadTime = lifetime
	}
	currExp := current.ExpiresAt
	if currExp == nil || currExp.IsZero() {
		defaultExp := now.Add(lifetime)
		if lerr == nil {
			defaultExp = now.Add(leadTime).Add(kms.KeyRotation.Overlap.Duration())
		}
		current.UpdateablePublicKeyMetadata.ExpiresAt = &unixtime.Unixtime{Time: defaultExp}
		if err := kms.PKs.Update(current.KID, current.UpdateablePublicKeyMetadata); err != nil {
			log.WithError(err).Error("PEMStorageKMS: automatic rotation: failed to update key expiration")
			currExp = &unixtime.Unixtime{Time: now}
		} else {
			currExp = current.ExpiresAt
		}
	}
	threshold := currExp.Time.Add(-kms.KeyRotation.Overlap.Duration()).Add(-leadTime)
	if !threshold.After(now) {
		kids := make([]string, len(algPKs))
		for i, pk := range algPKs {
			kids[i] = pk.KID
		}
		if earliestNbf, hasFuture, vErr := earliestFutureNbfForAlg(kms.PKs, alg, now); vErr == nil && hasFuture {
			shortenExpirationUntilFuture(
				kms.PKs, algPKs, earliestNbf, kms.KeyRotation.Overlap.Duration(), "PEMStorageKMS",
			)
			wait := time.Until(earliestNbf)
			if wait < minSleep {
				wait = minSleep
			}
			return wait, false
		}
		if err := kms.rotateKeys(kids, false, ""); err != nil {
			log.WithError(err).Error("PEMStorageKMS: automatic rotation: rotate failed")
			return minSleep, false
		}
		return 0, true
	}
	wait := time.Until(threshold)
	if wait < minSleep {
		wait = minSleep
	}
	return wait, false
}

// StopAutomaticRotation stops the background rotation loop and waits for it to exit.
func (kms *PEMStorageKMS) StopAutomaticRotation() {
	if kms.rotationStop == nil {
		return
	}
	close(kms.rotationStop)
	kms.rotationWG.Wait()
	log.Info("PEMStorageKMS: automatic rotation: stopped")
	kms.rotationStop = nil
}

// PEM helper functions

func readSignerFromPEM(data []byte, alg jwa.SignatureAlgorithm) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}
	var sk crypto.Signer
	var err error
	switch alg {
	case jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512():
		sk, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case jwa.ES256(), jwa.ES384(), jwa.ES512():
		sk, err = x509.ParseECPrivateKey(block.Bytes)
	case jwa.EdDSA():
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		var ok bool
		sk, ok = key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("not an Ed25519 Private Key")
		}
	default:
		return nil, errors.New("unknown signing algorithm: " + alg.String())
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return sk, nil
}

func exportRSAPrivateKeyAsPEM(privkey *rsa.PrivateKey) ([]byte, error) {
	privkeyBytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return privkeyPem, nil
}

func exportECPrivateKeyAsPEM(privkey *ecdsa.PrivateKey) ([]byte, error) {
	privkeyBytes, err := x509.MarshalECPrivateKey(privkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return privkeyPem, nil
}

func exportEDDSAPrivateKeyAsPEM(privkey ed25519.PrivateKey) ([]byte, error) {
	privkeyBytes, err := x509.MarshalPKCS8PrivateKey(privkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return privkeyPem, nil
}
