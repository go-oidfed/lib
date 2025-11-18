package kms

import (
	"cmp"
	"crypto"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zachmann/go-utils/fileutils"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/public"
	"github.com/go-oidfed/lib/unixtime"
)

// NewSingleAlgFilesystemKMS constructs a FilesystemKMS configured for a single
// signature algorithm, sharing the given PublicKeyStorage.
func NewSingleAlgFilesystemKMS(
	alg jwa.SignatureAlgorithm,
	config FilesystemKMSConfig, pks public.PublicKeyStorage,
) KeyManagementSystem {
	config.Algs = []jwa.SignatureAlgorithm{alg}
	config.DefaultAlg = alg
	return &FilesystemKMS{
		FilesystemKMSConfig: config,
		PKs:                 pks,
	}
}

// NewFilesystemKMSAndPublicKeyStorage creates a new FilesystemKMS and PublicKeyStorage
// backed by the same directory.
func NewFilesystemKMSAndPublicKeyStorage(config FilesystemKMSConfig) (KeyManagementSystem, error) {
	pks := &public.FilesystemPublicKeyStorage{
		Dir:    config.Dir,
		TypeID: config.TypeID,
	}
	if err := pks.Load(); err != nil {
		return nil, err
	}
	return &FilesystemKMS{
		FilesystemKMSConfig: config,
		PKs:                 pks,
	}, nil
}

// FilesystemKMSConfig is the configuration for a FilesystemKMS.
type FilesystemKMSConfig struct {
	KMSConfig
	Dir    string
	TypeID string
}

// FilesystemKMS implements KeyManagementSystem using PEM files for private keys
// on disk and a PublicKeyStorage for public key metadata.
type FilesystemKMS struct {
	FilesystemKMSConfig

	// signers is a map of all loaded signers, where the key is the kid
	signers map[string]crypto.Signer

	PKs public.PublicKeyStorage

	// automatic rotation control
	rotationStop chan struct{}
	rotationWG   sync.WaitGroup
}

func (kms *FilesystemKMS) legacyKeyFilePath(alg jwa.SignatureAlgorithm, future bool) string {
	var f string
	if future {
		f = "f"
	}
	return fmt.Sprintf("%s/%s_%s%s.pem", kms.Dir, kms.TypeID, alg.String(), f)
}

func (kms *FilesystemKMS) keyFilePath(kid string) string {
	return fmt.Sprintf("%s/%s.pem", kms.Dir, kid)
}

// GetDefault returns a crypto.Signer and the corresponding jwa.SignatureAlgorithm
func (kms *FilesystemKMS) GetDefault() (crypto.Signer, jwa.SignatureAlgorithm) {
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
func (kms *FilesystemKMS) GetForAlgs(algs ...string) (
	crypto.Signer,
	jwa.SignatureAlgorithm,
) {
	activePKs, err := kms.PKs.GetActive()
	if err != nil {
		log.WithError(err).Error("FilesystemKMS: failed to get active public keys")
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

// Load loads the private keys from disk and generates missing keys when
// configured to do so.
func (kms *FilesystemKMS) Load() error {
	log.Debugf("FilesystemKMS: loading keys from '%s'", kms.Dir)
	if kms.signers == nil {
		kms.signers = make(map[string]crypto.Signer)
	}

	log.Debug("FilesystemKMS: loading active pks")
	activePKs, err := kms.PKs.GetActive()
	if err != nil {
		return err
	}
	log.Debugf("FilesystemKMS: found %d active keys in pk storage", len(activePKs))
	// initialize map before use
	var loadedAlgs map[jwa.SignatureAlgorithm]struct{}
	loadedAlgs = make(map[jwa.SignatureAlgorithm]struct{})
	for _, activePK := range activePKs {
		kid := activePK.KID
		kalg, _ := activePK.Key.Algorithm()
		alg := kalg.(jwa.SignatureAlgorithm)
		signer, err := jwx.ReadSignerFromFile(kms.keyFilePath(kid), alg)
		if err != nil {
			log.WithError(err).WithField("kid", kid).Warn("FilesystemKMS: could not load signing key")
		} else {
			kms.signers[kid] = signer
			loadedAlgs[alg] = struct{}{}
		}
	}
	log.Debugf("FilesystemKMS: loaded %d active keys", len(kms.signers))

	log.Debug("FilesystemKMS: Checking that all signing algs have a valid key")
	for _, alg := range kms.Algs {
		if _, ok := loadedAlgs[alg]; ok {
			log.WithField("alg", alg.String()).Debug("FilesystemKMS: key for alg already found")
			continue
		}
		log.WithField("alg", alg.String()).Debug("FilesystemKMS: key for alg is missing")
		err = kms.loadLegacyOrGenerateSigner(alg)
		if err != nil {
			return err
		}
	}
	return nil
}

// loadLegacyOrGenerateSigner loads a signer from a legacy location or generates
// a new one if it doesn't exist (and generation is enabled).
func (kms *FilesystemKMS) loadLegacyOrGenerateSigner(alg jwa.SignatureAlgorithm) error {
	log.WithField("alg", alg.String()).Debug("FilesystemKMS: Try loading key from legacy")
	filePath := kms.legacyKeyFilePath(alg, false)
	signer, err := jwx.ReadSignerFromFile(filePath, alg)
	if err == nil {
		log.WithField("alg", alg.String()).Debug("FilesystemKMS: Found legacy key")
		pk, kid, err := jwx.SignerToPublicJWK(signer, alg)
		if err != nil {
			return err
		}
		kms.signers[kid] = signer
		if !fileutils.FileExists(kms.keyFilePath(kid)) {
			log.WithField("alg", alg.String()).WithField(
				"kid", kid,
			).Debug("FilesystemKMS: Writing legacy key to new key file")
			if err = jwx.WriteSignerToFile(signer, kms.keyFilePath(kid)); err != nil {
				return err
			}
		} else {
			log.WithField("alg", alg.String()).WithField(
				"kid", kid,
			).Debug("FilesystemKMS: legacy key already have been written to new key file")
		}
		storedPK, err := kms.PKs.Get(kid)
		if err != nil {
			return err
		}
		var expF float64
		_ = pk.Get("exp", &expF)
		var exp unixtime.Unixtime
		if expF != 0 {
			sec, dec := math.Modf(expF)
			exp = unixtime.Unixtime{Time: time.Unix(int64(sec), int64(dec*(1e9)))}
		}
		if storedPK != nil {
			log.WithField("alg", alg.String()).WithField("kid", kid).Debug("FilesystemKMS: Legacy key already loaded")
			if storedPK.ExpiresAt.IsZero() || exp.After(time.Now()) {
				return nil
			}
		} else {
			var iatF, nbfF float64
			_ = pk.Get("iat", &iatF)
			_ = pk.Get("nbf", &nbfF)
			var iat, nbf unixtime.Unixtime
			if iatF != 0 {
				sec, dec := math.Modf(iatF)
				iat = unixtime.Unixtime{Time: time.Unix(int64(sec), int64(dec*(1e9)))}
			}
			if nbfF != 0 {
				sec, dec := math.Modf(nbfF)
				nbf = unixtime.Unixtime{Time: time.Unix(int64(sec), int64(dec*(1e9)))}
			}
			if kms.KeyRotation.Enabled {
				newExp := unixtime.Unixtime{Time: time.Now().Add(kms.KeyRotation.Interval.Duration())}
				if exp.Before(newExp.Time) {
					exp = newExp
				}
			}
			pke := public.PublicKeyEntry{
				KID:       kid,
				Key:       pk,
				IssuedAt:  iat,
				NotBefore: nbf,
				UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{
					ExpiresAt: exp,
				},
			}
			if err = kms.PKs.Add(pke); err != nil {
				return err
			}
			if exp.IsZero() || exp.After(time.Now()) {
				log.WithField("alg", alg.String()).WithField(
					"kid", kid,
				).Info("FilesystemKMS: Successfully loaded legacy key")
				return nil
			}
		}
		log.WithField("alg", alg.String()).WithField("kid", kid).Info("FilesystemKMS: legacy key is expired")
	}
	log.WithField("alg", alg.String()).Info("FilesystemKMS: no valid signing key found")
	// could not load key
	if !kms.GenerateKeys {
		log.Info("FilesystemKMS: key generation disabled")
		return errors.Errorf(
			"no existing signing key for alg '%s'. "+
				"Assure the file exists and has the correct format or enable key generation.", alg,
		)
	}
	log.Info("FilesystemKMS: generating new signing key")
	// Could not load key, generating a new one for this alg
	_, err = kms.generateNewSigner(alg, nbfModeNow)
	return err
}

func (kms *FilesystemKMS) generateNewSigner(
	alg jwa.SignatureAlgorithm,
	mode nbfMode,
) (*public.PublicKeyEntry, error) {
	sk, pk, kid, err := jwx.GenerateKeyPair(alg, kms.RSAKeyLen)
	if err != nil {
		return nil, err
	}
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
		KID:       kid,
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
	if err = jwx.WriteSignerToFile(sk, kms.keyFilePath(kid)); err != nil {
		return nil, err
	}
	kms.signers[kid] = sk
	return &pke, nil
}

func (kms *FilesystemKMS) rotateKeys(kids []string, revoked bool, reason string) error {
	log.WithFields(
		log.Fields{
			"kids":    kids,
			"revoked": revoked,
		},
	).Info("FilesystemKMS: rotation: start")
	ks := make([]*public.PublicKeyEntry, len(kids))
	var signingAlg jwa.SignatureAlgorithm
	// Track latest expiration across keys to decide nbf mode for new key
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
	).Info("FilesystemKMS: rotation: generated new key")
	newExpForOldKey := unixtime.Unixtime{Time: pk.NotBefore.Add(kms.KeyRotation.Overlap.Duration())}
	for _, k := range ks {
		if revoked {
			k.RevokedAt = unixtime.Now()
			k.Reason = reason
		}
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
	).Info("FilesystemKMS: rotation: completed")
	return nil
}

func (kms *FilesystemKMS) RotateKey(kid string, revoked bool, reason string) error {
	log.WithFields(
		log.Fields{
			"kid":     kid,
			"revoked": revoked,
		},
	).Info("FilesystemKMS: rotate key")
	return kms.rotateKeys([]string{kid}, revoked, reason)
}

// RotateAllKeys rotates all active keys per configured algorithm, optionally
// marking them revoked and recording a reason.
func (kms *FilesystemKMS) RotateAllKeys(revoked bool, reason string) error {
	// Get all currently active public keys
	activePKs, err := kms.PKs.GetActive()
	if err != nil {
		return err
	}

	// Group active keys by algorithm
	pksByAlg := activePKs.ByAlg()

	// Iterate over configured algorithms only
	for _, alg := range kms.Algs {
		algPKs, ok := pksByAlg[alg]
		if !ok || len(algPKs) == 0 {
			// Nothing to rotate for this algorithm; create a new key
			if _, err = kms.generateNewSigner(alg, nbfModeNow); err != nil {
				return err
			}
			log.WithField(
				"alg", alg.String(),
			).Info("FilesystemKMS: rotation: seeded new key for alg with no active keys")
		}

		kids := make([]string, len(algPKs))
		for i, pk := range algPKs {
			kids[i] = pk.KID
		}
		log.WithField("alg", alg.String()).Info("FilesystemKMS: rotation: processing alg")
		if err = kms.rotateKeys(kids, revoked, reason); err != nil {
			return err
		}
	}
	return nil
}

// StartAutomaticRotation starts a background loop that monitors key expiration
// thresholds and rotates keys ahead of time based on the configured overlap.
func (kms *FilesystemKMS) StartAutomaticRotation() error {
	if !kms.KeyRotation.Enabled {
		return nil
	}
	// ensure only one rotation loop runs
	if kms.rotationStop != nil {
		return nil
	}
	log.Info("FilesystemKMS: automatic rotation: starting")
	kms.rotationStop = make(chan struct{})
	kms.rotationWG.Add(1)
	go func() {
		defer kms.rotationWG.Done()
		for {
			nextSleep, didRotate := kms.rotationStep(time.Now())
			if didRotate {
				select {
				case <-kms.rotationStop:
					return
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
				// loop
			}
		}
	}()
	return nil
}

// rotationStep performs one evaluation/rotation cycle and returns the next sleep
// interval and whether any rotation or seeding occurred (didRotate).
func (kms *FilesystemKMS) rotationStep(now time.Time) (time.Duration, bool) {
	nextSleep := kms.KeyRotation.Overlap.Duration() / 2
	const minSleep = time.Second
	if nextSleep <= 0 {
		nextSleep = minSleep
	}
	didRotate := false

	activePKs, err := kms.PKs.GetActive()
	if err != nil {
		log.WithError(err).Error("FilesystemKMS: automatic rotation: failed to get active public keys")
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
	return nextSleep, didRotate
}

// rotationEvaluationForAlg evaluates rotation needs for a single algorithm.
// It returns a candidate sleep duration until the next action point and whether
// any rotation or seeding occurred.
func (kms *FilesystemKMS) rotationEvaluationForAlg(
	pksByAlg map[jwa.SignatureAlgorithm]public.PublicKeyEntryList,
	alg jwa.SignatureAlgorithm,
	now time.Time,
	minSleep time.Duration,
) (time.Duration, bool) {
	algPKs, ok := pksByAlg[alg]
	if !ok || len(algPKs) == 0 {
		earliestNbf, hasFuture, vErr := earliestFutureNbfForAlg(kms.PKs, alg, now)
		if vErr != nil {
			log.WithError(vErr).Error("FilesystemKMS: automatic rotation: failed to get valid public keys for future check")
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
			log.WithError(err).Error("FilesystemKMS: automatic rotation: failed to seed key for alg")
			return minSleep, false
		}
		return 0, true
	}

	current := slices.MaxFunc(
		algPKs, func(a, b public.PublicKeyEntry) int {
			return cmp.Compare(a.ExpiresAt.Unix(), b.ExpiresAt.Unix())
		},
	)

	lifetime := time.Duration(0)
	if kms.KeyRotation.EntityConfigurationLifetimeFunc != nil {
		if lt, lerr := kms.KeyRotation.EntityConfigurationLifetimeFunc(); lerr == nil {
			lifetime = lt
		} else {
			log.WithError(lerr).Warn("FilesystemKMS: automatic rotation: failed to get lifetime; using 0")
		}
	}
	threshold := current.ExpiresAt.Time.Add(-kms.KeyRotation.Overlap.Duration()).Add(-lifetime)
	if !threshold.After(now) {
		kids := make([]string, len(algPKs))
		for i, pk := range algPKs {
			kids[i] = pk.KID
		}
		if earliestNbf, hasFuture, vErr := earliestFutureNbfForAlg(kms.PKs, alg, now); vErr == nil && hasFuture {
			shortenExpirationUntilFuture(
				kms.PKs, algPKs, earliestNbf, kms.KeyRotation.Overlap.Duration(), "FilesystemKMS",
			)
			wait := time.Until(earliestNbf)
			if wait < minSleep {
				wait = minSleep
			}
			return wait, false
		}
		if err := kms.rotateKeys(kids, false, ""); err != nil {
			log.WithError(err).Error("FilesystemKMS: automatic rotation: rotate failed")
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

// earliestFutureNbfForAlg returns the earliest NotBefore among valid, non-revoked
// keys for the given algorithm, that are in the future relative to now.
// Removed local earliestFutureNbfForAlg and shortenExpirationUntilFuture in favor of shared helpers.

// StopAutomaticRotation stops the background rotation loop and waits for it to exit.
func (kms *FilesystemKMS) StopAutomaticRotation() {
	if kms.rotationStop == nil {
		return
	}
	close(kms.rotationStop)
	kms.rotationWG.Wait()
	log.Info("FilesystemKMS: automatic rotation: stopped")
	kms.rotationStop = nil
}
