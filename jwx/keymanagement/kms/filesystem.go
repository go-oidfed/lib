package kms

import (
	"cmp"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// GetPendingChanges returns the pending alg and default change, if any.
func (kms *FilesystemKMS) GetPendingChanges() (*PendingAlgChange, *PendingDefaultChange) {
	loadedState, err := kms.loadScheduledState()
	if err != nil {
		log.WithError(err).Error("FilesystemKMS: failed to load scheduled state")
		return nil, nil
	}
	return loadedState.PendingAlgChange, loadedState.PendingDefaultChange
}

// GetDefaultAlg returns the default algorithm
func (kms *FilesystemKMS) GetDefaultAlg() jwa.SignatureAlgorithm {
	return kms.DefaultAlg
}

// GetAlgs returns the configured algorithms
func (kms *FilesystemKMS) GetAlgs() []jwa.SignatureAlgorithm {
	return kms.Algs
}

func (kms *FilesystemKMS) stateFilePath() string {
	return fmt.Sprintf("%s/%s", kms.Dir, "kms_state.json")
}

func (kms *FilesystemKMS) loadScheduledState() (scheduledState, error) {
	var st scheduledState
	f := kms.stateFilePath()
	b, err := os.ReadFile(f)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return st, err
	}
	if len(b) == 0 {
		return st, nil
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	return st, nil
}

func (kms *FilesystemKMS) saveScheduledState(st scheduledState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	p := kms.stateFilePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

// ChangeAlgs updates the set of configured signature algorithms.
// It stops automatic rotation (if running), replaces the algorithms,
// reloads/generates keys as needed via Load, and restarts rotation
// if rotation is enabled. No-op when the set is unchanged.
func (kms *FilesystemKMS) ChangeAlgs(algs []jwa.SignatureAlgorithm) error {
	// Only act if the set of algs actually changes
	if slices.Equal(kms.Algs, algs) {
		return nil
	}
	if !kms.GenerateKeys {
		return errors.New("changing algorithms dynamically (without a restart) is not supported when key generation is disabled")
	}
	kms.StopAutomaticRotation()
	kms.Algs = algs
	// Reload to reflect new alg set; generate if enabled
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
func (kms *FilesystemKMS) ChangeGenerateKeys(generate bool) error {
	if kms.GenerateKeys == generate {
		return nil
	}
	kms.GenerateKeys = generate
	// If enabling generation, ensure missing keys are created
	if generate {
		return kms.Load()
	}
	return nil
}

// ChangeRSAKeyLength sets the RSA key length to be used for
// future key generation. Existing keys are unaffected.
func (kms *FilesystemKMS) ChangeRSAKeyLength(length int) error {
	if kms.RSAKeyLen == length {
		return nil
	}
	kms.RSAKeyLen = length
	return nil
}

// ChangeDefaultAlgorithm sets the default algorithm used when
// selecting a signer without an explicit alg preference. The
// algorithm must be part of the configured set.
func (kms *FilesystemKMS) ChangeDefaultAlgorithm(alg jwa.SignatureAlgorithm) error {
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
func (kms *FilesystemKMS) ChangeDefaultAlgorithmAt(alg jwa.SignatureAlgorithm, effectiveAt unixtime.Unixtime) error {
	if alg.String() == "" {
		return errors.New("invalid algorithm")
	}
	// Early no-op if nothing would change: if the requested default equals the
	// current default AND there is no differing pending default change.
	st, err := kms.loadScheduledState()
	if err != nil {
		return err
	}
	// If an identical pending change already exists, no-op
	if st.PendingDefaultChange != nil &&
		st.PendingDefaultChange.Alg.String() == alg.String() &&
		st.PendingDefaultChange.EffectiveAt.Equal(effectiveAt.Time) {
		return nil
	}
	if kms.DefaultAlg.String() == alg.String() {
		// Same as current. Only schedule if there is a pending change that differs
		// (so this call would effectively replace it).
		if st.PendingDefaultChange == nil || (st.PendingDefaultChange != nil &&
			st.PendingDefaultChange.Alg.String() == alg.String() &&
			st.PendingDefaultChange.EffectiveAt.Equal(effectiveAt.Time)) {
			// Either no pending change, or identical pending -> nothing to do
			return nil
		}
	} else {
		// Validate that requested alg is within configured set if you require it.
		// We keep prior behavior: allow even if not in kms.Algs, as alg set may change separately.
	}
	// Allow scheduling even if alg is not currently in kms.Algs. The actual
	// alg set switch might be scheduled separately via ChangeAlgsAt.
	if !kms.GenerateKeys {
		return errors.New("scheduling default algorithm change requires key generation to be enabled")
	}
	// Ensure a future-dated key exists only when we're actually going to schedule
	if err := kms.ensureFutureKey(alg, effectiveAt.Time); err != nil {
		return err
	}
	// Persist schedule
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
func (kms *FilesystemKMS) ChangeKeyRotationConfig(config KeyRotationConfig) error {
	// Only act if something meaningful changed
	prev := kms.KeyRotation
	kms.KeyRotation = config
	same := prev.Enabled == config.Enabled &&
		prev.Interval.Duration() == config.Interval.Duration() &&
		prev.Overlap.Duration() == config.Overlap.Duration()
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
			noExpIndex := -1
			maxExpIndex := -1
			maxExpWithNbfIndex := -1
			nbfTreshold := time.Now().Add(-kms.KeyRotation.Overlap.Duration() / 2)
			for i, it := range algPKs {
				if it.ExpiresAt == nil {
					noExpIndex = i
					continue
				}
				if it.NotBefore != nil && it.NotBefore.Before(nbfTreshold) && it.ExpiresAt.After(
					maxExpWithNbf.Time,
				) {
					maxExpWithNbf = *it.ExpiresAt
					maxExpWithNbfIndex = i

				} else if maxExpIndex == -1 && it.ExpiresAt.After(maxExp.Time) {
					maxExp = *it.ExpiresAt
					maxExpIndex = i
				}
			}
			if maxExpWithNbfIndex != -1 {
				pk = algPKs[maxExpWithNbfIndex]
			} else if maxExpIndex != -1 {
				pk = algPKs[maxExpIndex]
			} else {
				pk = algPKs[noExpIndex]
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
		if !kms.GenerateKeys {
			log.Info("FilesystemKMS: key generation disabled")
			return errors.Errorf(
				"no existing signing key for alg '%s'. Assure the file exists and has the correct format or enable key generation.",
				alg,
			)
		}
		log.Info("FilesystemKMS: generating new signing key")
		if _, err = kms.generateNewSigner(alg, nbfModeNow); err != nil {
			return err
		}
	}
	return nil
}

// NewFilesystemKMSFromBasic creates a new FilesystemKMS initialized from an existing
// BasicKeyManagementSystem and persists private keys for the configured algorithms
// into the filesystem at the configured directory.
func NewFilesystemKMSFromBasic(
	src BasicKeyManagementSystem,
	config FilesystemKMSConfig,
	pks public.PublicKeyStorage,
) (KeyManagementSystem, error) {
	kms := &FilesystemKMS{
		FilesystemKMSConfig: config,
		PKs:                 pks,
		signers:             make(map[string]crypto.Signer),
	}

	// Ensure target PK storage is loaded
	if err := pks.Load(); err != nil {
		return nil, err
	}

	// For each configured algorithm, obtain a signer from the source and persist it
	for _, alg := range config.Algs {
		signer, usedAlg := src.GetForAlgs(alg.String())
		if signer == nil || usedAlg.String() == "" {
			continue
		}
		pk, kid, err := jwx.SignerToPublicJWK(signer, usedAlg)
		if err != nil {
			return nil, err
		}
		// Write private key to new location
		if err = jwx.WriteSignerToFile(signer, kms.keyFilePath(kid)); err != nil {
			return nil, err
		}
		// Register signer locally
		kms.signers[kid] = signer
		// Add public key metadata to PK storage if missing
		existing, err := pks.Get(kid)
		if err != nil {
			return nil, err
		}
		if existing == nil {
			now := unixtime.Now()
			pke := public.PublicKeyEntry{
				KID:       kid,
				Key:       public.JWKKey{Key: pk},
				IssuedAt:  &now,
				NotBefore: &now,
			}
			if err = pks.Add(pke); err != nil {
				return nil, err
			}
		}
	}

	// Finalize by loading any remaining keys normally
	if err := kms.Load(); err != nil {
		log.WithError(err).Warn("NewFilesystemKMSFromBasic: Load encountered issues after migration")
	}
	return kms, nil
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
	var nbf *unixtime.Unixtime
	switch mode {
	case nbfModeNow:
		nbf = &now
	case nbfModeNext:
		lifetime, err := kms.KeyRotation.EntityConfigurationLifetimeFunc()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get entity configuration lifetime")
		}
		nbf = &unixtime.Unixtime{Time: now.Add(lifetime)}
	case nbfModeAt:
		// Should not hit here; use generateNewSignerAt to pass explicit time.
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
	if err = jwx.WriteSignerToFile(sk, kms.keyFilePath(kid)); err != nil {
		return nil, err
	}
	kms.signers[kid] = sk
	return &pke, nil
}

// generateNewSignerAt generates a signer with a specific NotBefore time.
func (kms *FilesystemKMS) generateNewSignerAt(
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
	if err = jwx.WriteSignerToFile(sk, kms.keyFilePath(kid)); err != nil {
		return nil, err
	}
	kms.signers[kid] = sk
	return &pke, nil
}

// ensureFutureKey ensures there exists at least one non-revoked key for the
// given alg with NotBefore >= effectiveAt. If not, it generates one.
func (kms *FilesystemKMS) ensureFutureKey(alg jwa.SignatureAlgorithm, effectiveAt time.Time) error {
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
func (kms *FilesystemKMS) ChangeAlgsAt(
	algs []jwa.SignatureAlgorithm, effectiveAt unixtime.Unixtime, overlap time.Duration,
) error {
	if len(algs) == 0 {
		return errors.New("algs must not be empty")
	}
	// Load current pending state to decide if there is anything to change
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

	// If there is already an identical pending change, no-op
	if st.PendingAlgChange != nil &&
		evalPendingAlgEqual() &&
		st.PendingAlgChange.EffectiveAt.Equal(effectiveAt.Time) &&
		st.PendingAlgChange.Overlap.Duration == overlap {
		return nil
	}
	// If requested set equals current set and there's no differing pending change, do nothing
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
	// Pre-generate future keys for new algs (only if we actually schedule)
	for _, alg := range algs {
		if err := kms.ensureFutureKey(alg, effectiveAt.Time); err != nil {
			return err
		}
	}
	// Extend expiration for old algs not present in new set
	active, err := kms.PKs.GetActive()
	if err != nil {
		return err
	}
	newSet := make(map[string]struct{})
	for _, a := range algs {
		newSet[a.String()] = struct{}{}
	}
	// Determine overlap expiration target
	targetExp := &unixtime.Unixtime{Time: effectiveAt.Add(overlap)}
	byAlg := active.ByAlg()
	for alg, list := range byAlg {
		if _, ok := newSet[alg.String()]; ok {
			// stays; nothing to shorten here
			continue
		}
		// shorten old algs
		for _, k := range list {
			if k.ExpiresAt == nil || k.ExpiresAt.IsZero() || targetExp.Before(k.ExpiresAt.Time) {
				k.ExpiresAt = targetExp
				if err = kms.PKs.Update(k.KID, k.UpdateablePublicKeyMetadata); err != nil {
					log.WithError(err).Error("FilesystemKMS: schedule algs: failed to update old key exp")
				}
			}
		}
	}
	// Persist schedule
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
		if k.ExpiresAt != nil && !k.ExpiresAt.IsZero() && (latestExp.IsZero() || k.ExpiresAt.After(latestExp)) {
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
			log.WithError(err).Error("FilesystemKMS: rotation: failed to update key")
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

// RotateKey rotates a single key, optionally marking it revoked and recording a reason.
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
	const minSleep = time.Second
	nextSleep := max(kms.KeyRotation.Overlap.Duration()/2, minSleep)
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
	// Consider scheduled changes
	if st, err := kms.loadScheduledState(); err == nil {
		// Helper to apply alg change
		applyAlg := func(p *PendingAlgChange) bool {
			if p == nil {
				return false
			}
			if !now.Before(p.EffectiveAt.Time) {
				kms.Algs = p.Algs
				// Refresh signers after alg change
				if err := kms.Load(); err != nil {
					log.WithError(err).Error("FilesystemKMS: scheduled alg change: load failed")
				}
				st.PendingAlgChange = nil
				if err := kms.saveScheduledState(st); err != nil {
					log.WithError(err).Error("FilesystemKMS: scheduled alg change: save state failed")
				}
				return true
			}
			wait := time.Until(p.EffectiveAt.Time)
			if wait > 0 && wait < nextSleep {
				nextSleep = wait
			}
			return false
		}
		// Helper to apply default change
		applyDef := func(p *PendingDefaultChange) bool {
			if p == nil {
				return false
			}
			if !now.Before(p.EffectiveAt.Time) {
				kms.DefaultAlg = p.Alg
				st.PendingDefaultChange = nil
				if err = kms.saveScheduledState(st); err != nil {
					log.WithError(err).Error("FilesystemKMS: scheduled default change: save state failed")
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
		log.WithError(err).Error("FilesystemKMS: scheduled state load failed")
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
		log.WithField("alg", alg.String()).Info("FilesystemKMS: automatic rotation: seeded new key for alg")
		return 0, true
	}

	current := slices.MaxFunc(
		algPKs, func(a, b public.PublicKeyEntry) int {
			// Safely compare expiration when one or both are nil.
			// Treat nil (no expiration) as the earliest time to force rotation handling.
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
			log.WithError(lerr).Warn("FilesystemKMS: automatic rotation: failed to get lifetime; using 0")
		}
	}
	currExp := current.ExpiresAt
	if currExp == nil || currExp.IsZero() {
		current.UpdateablePublicKeyMetadata.ExpiresAt = &unixtime.Unixtime{Time: now.Add(lifetime)}
		if err := kms.PKs.Update(current.KID, current.UpdateablePublicKeyMetadata); err != nil {
			log.WithError(err).Error("FilesystemKMS: automatic rotation: failed to update key expiration")
			currExp = &unixtime.Unixtime{Time: now}
		} else {
			currExp = current.ExpiresAt
		}
	}
	// Use currExp (ensured non-nil) for threshold calculation
	threshold := currExp.Time.Add(-kms.KeyRotation.Overlap.Duration()).Add(-lifetime)
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
