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
		log.WithError(err).Error("failed to get active public keys")
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
			log.WithError(err).WithField("kid", kid).Warn("could not load signing key")
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
	log.WithField("alg", alg.String()).Debug("Try loading key from legacy")
	filePath := kms.legacyKeyFilePath(alg, false)
	signer, err := jwx.ReadSignerFromFile(filePath, alg)
	if err == nil {
		log.WithField("alg", alg.String()).Debug("Found legacy key")
		pk, kid, err := jwx.SignerToPublicJWK(signer, alg)
		if err != nil {
			return err
		}
		kms.signers[kid] = signer
		if !fileutils.FileExists(kms.keyFilePath(kid)) {
			log.WithField("alg", alg.String()).WithField("kid", kid).Debug("Writing legacy key to new key file")
			if err = jwx.WriteSignerToFile(signer, kms.keyFilePath(kid)); err != nil {
				return err
			}
		} else {
			log.WithField("alg", alg.String()).WithField(
				"kid", kid,
			).Debug("legacy key already have been written to new key file")
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
			log.WithField("alg", alg.String()).WithField("kid", kid).Debug("Legacy key already loaded")
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
				log.WithField("alg", alg.String()).WithField("kid", kid).Info("Successfully loaded legacy key")
				return nil
			}
		}
		log.WithField("alg", alg.String()).WithField("kid", kid).Info("legacy key is expired")
	}
	log.WithField("alg", alg.String()).Info("no valid signing key found")
	// could not load key
	if !kms.GenerateKeys {
		log.Info("key generation disabled")
		return errors.Errorf(
			"no existing signing key for alg '%s'. "+
				"Assure the file exists and has the correct format or enable key generation.", alg,
		)
	}
	log.Info("generating new signing key")
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
	return nil
}

func (kms *FilesystemKMS) RotateKey(kid string, revoked bool, reason string) error {
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
		}

		kids := make([]string, len(algPKs))
		for i, pk := range algPKs {
			kids[i] = pk.KID
		}
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
	kms.rotationStop = make(chan struct{})
	kms.rotationWG.Add(1)
	go func() {
		defer kms.rotationWG.Done()
		// helper to compute next wait duration and perform rotations if needed
		for {
			now := time.Now()
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
				log.WithError(err).Error("automatic rotation: failed to get active public keys")
			} else {
				pksByAlg := activePKs.ByAlg()
				// iterate only configured algorithms
				for _, alg := range kms.Algs {
					algPKs, ok := pksByAlg[alg]
					if !ok || len(algPKs) == 0 {
						// No active keys: before seeding a new one, check if a valid future key already exists.
						// If a future key is present (nbf > now and not revoked/expired), wait until it becomes active
						// instead of generating more keys.
						validPKs, vErr := kms.PKs.GetValid()
						if vErr != nil {
							log.WithError(vErr).Error("automatic rotation: failed to get valid public keys for future check")
						} else {
							// find earliest future nbf for this alg
							earliestNbf := time.Time{}
							for _, pk := range validPKs {
								algI, set := pk.Key.Algorithm()
								if !set {
									continue
								}
								if a, ok := algI.(jwa.SignatureAlgorithm); !ok || a.String() != alg.String() {
									continue
								}
								// skip revoked
								if !pk.RevokedAt.IsZero() && pk.RevokedAt.Before(now) {
									continue
								}
								// consider only future keys
								if !pk.NotBefore.IsZero() && pk.NotBefore.After(now) {
									if earliestNbf.IsZero() || pk.NotBefore.Before(earliestNbf) {
										earliestNbf = pk.NotBefore.Time
									}
								}
							}
							if !earliestNbf.IsZero() {
								// schedule sleep until the future key becomes active
								wait := time.Until(earliestNbf)
								if wait < minSleep {
									wait = minSleep
								}
								if wait < nextSleep {
									nextSleep = wait
								}
								// do not seed a new key; continue to next alg
								continue
							}
						}
						// no active and no future key; seed a new key immediately
						if _, err := kms.generateNewSigner(alg, nbfModeNow); err != nil {
							log.WithError(err).Error("automatic rotation: failed to seed key for alg")
							// ensure we don't spin; retry soon-ish
							if nextSleep > minSleep {
								nextSleep = minSleep
							}
							continue
						}
						// re-evaluate immediately to include the new key in active set
						didRotate = true
						continue
					}
					// pick the key with latest expiration as the current signer for this alg
					current := slices.MaxFunc(
						algPKs, func(a, b public.PublicKeyEntry) int {
							return cmp.Compare(a.ExpiresAt.Unix(), b.ExpiresAt.Unix())
						},
					)
					// Trigger rotation early enough to accommodate future nbf = now + lifetime
					lifetime := time.Duration(0)
					if kms.KeyRotation.EntityConfigurationLifetimeFunc != nil {
						if lt, lerr := kms.KeyRotation.EntityConfigurationLifetimeFunc(); lerr == nil {
							lifetime = lt
						} else {
							log.WithError(lerr).Warn("automatic rotation: failed to get lifetime; using 0")
						}
					}
					threshold := current.ExpiresAt.Time.Add(-kms.KeyRotation.Overlap.Duration()).Add(-lifetime)
					// if rotation needed now or in the past, rotate this algorithm set
					if !threshold.After(now) {
						// collect all kids for this alg to rotate cohesively
						kids := make([]string, len(algPKs))
						for i, pk := range algPKs {
							kids[i] = pk.KID
						}
						// Before rotating, check whether there is already a future key present for this alg.
						// If so, skip generating yet another key and just shorten old exp via rotate (still needed).
						// We detect a future key via GetValid() with nbf > now.
						hasFuture := false
						if validPKs, vErr := kms.PKs.GetValid(); vErr == nil {
							for _, pk := range validPKs {
								algI, set := pk.Key.Algorithm()
								if !set {
									continue
								}
								if a, ok := algI.(jwa.SignatureAlgorithm); !ok || a.String() != alg.String() {
									continue
								}
								if !pk.RevokedAt.IsZero() && pk.RevokedAt.Before(now) {
									continue
								}
								if !pk.NotBefore.IsZero() && pk.NotBefore.After(now) {
									hasFuture = true
									break
								}
							}
						}
						if hasFuture {
							// If a future key exists, do not generate another. Instead, only shorten old keys' exp.
							// Achieve this by computing overlap end relative to earliest future nbf, and updating old keys.
							earliestNbf := time.Time{}
							if validPKs, vErr := kms.PKs.GetValid(); vErr == nil {
								for _, pk := range validPKs {
									algI, set := pk.Key.Algorithm()
									if !set {
										continue
									}
									if a, ok := algI.(jwa.SignatureAlgorithm); !ok || a.String() != alg.String() {
										continue
									}
									if !pk.RevokedAt.IsZero() && pk.RevokedAt.Before(now) {
										continue
									}
									if !pk.NotBefore.IsZero() && pk.NotBefore.After(now) {
										if earliestNbf.IsZero() || pk.NotBefore.Before(earliestNbf) {
											earliestNbf = pk.NotBefore.Time
										}
									}
								}
							}
							if !earliestNbf.IsZero() {
								newExpForOldKey := unixtime.Unixtime{Time: earliestNbf.Add(kms.KeyRotation.Overlap.Duration())}
								for _, k := range algPKs {
									if k.ExpiresAt.IsZero() || newExpForOldKey.Before(k.ExpiresAt.Time) {
										k.ExpiresAt = newExpForOldKey
										if uErr := kms.PKs.Update(k.KID, k.UpdateablePublicKeyMetadata); uErr != nil {
											log.WithError(uErr).Error("automatic rotation: failed to update old key exp")
										}
									}
								}
								// schedule re-check at earliestNbf to let future key become active
								wait := time.Until(earliestNbf)
								if wait < minSleep {
									wait = minSleep
								}
								if wait < nextSleep {
									nextSleep = wait
								}
								// nothing else to do for this alg
								continue
							}
						}
						if err = kms.rotateKeys(kids, false, ""); err != nil {
							log.WithError(err).Error("automatic rotation: rotate failed")
							// on error, retry after a short delay
							if nextSleep > minSleep {
								nextSleep = minSleep
							}
						} else {
							didRotate = true
						}
						// after rotation, we will recompute immediately in next loop iteration
						continue
					}
					// compute earliest threshold across algorithms
					wait := time.Until(threshold)
					if wait < nextSleep {
						nextSleep = wait
					}
				}
			}

			if didRotate {
				// Immediately re-evaluate without sleeping to compute next threshold
				select {
				case <-kms.rotationStop:
					return
				default:
				}
				continue
			}

			// sleep until the earliest threshold or default duration
			if nextSleep <= 0 {
				nextSleep = minSleep
			}
			timer := time.NewTimer(nextSleep)
			select {
			case <-kms.rotationStop:
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
				// loop and re-evaluate
			}
		}
	}()
	return nil
}

// StopAutomaticRotation stops the background rotation loop and waits for it to exit.
func (kms *FilesystemKMS) StopAutomaticRotation() {
	if kms.rotationStop == nil {
		return
	}
	close(kms.rotationStop)
	kms.rotationWG.Wait()
	kms.rotationStop = nil
}
