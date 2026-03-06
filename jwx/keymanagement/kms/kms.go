package kms

import (
	"crypto"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	log "github.com/sirupsen/logrus"
	"github.com/zachmann/go-utils/duration"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/public"
	"github.com/go-oidfed/lib/unixtime"
)

type nbfMode int

const (
	nbfModeNow nbfMode = iota
	nbfModeNext
	// nbfModeAt is used internally when a specific NotBefore timestamp
	// should be set for a newly generated key.
	nbfModeAt
)

// BasicKeyManagementSystem provides methods to load keys and retrieve
// a default or algorithm-specific signer.
type BasicKeyManagementSystem interface {
	Load() error
	GetForAlgs(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm)
	GetDefault() (crypto.Signer, jwa.SignatureAlgorithm)
	GetAlgs() []jwa.SignatureAlgorithm
	GetDefaultAlg() jwa.SignatureAlgorithm
}

// KeyManagementSystem extends BasicKeyManagementSystem with rotation and
// automatic rotation controls.
type KeyManagementSystem interface {
	BasicKeyManagementSystem
	RotateKey(kid string, revoked bool, reason string) error
	RotateAllKeys(revoked bool, reason string) error
	StartAutomaticRotation() error
	StopAutomaticRotation()
	ChangeGenerateKeys(generate bool) error
	ChangeAlgs(algs []jwa.SignatureAlgorithm) error
	ChangeDefaultAlgorithm(alg jwa.SignatureAlgorithm) error
	ChangeRSAKeyLength(length int) error
	ChangeKeyRotationConfig(config KeyRotationConfig) error
	// ChangeAlgsAt schedules an algorithm set change to take effect
	// at the given point in time. Until then, existing algorithms
	// remain active. Old algorithms will be kept valid until
	// effectiveAt + overlap.
	ChangeAlgsAt(algs []jwa.SignatureAlgorithm, effectiveAt unixtime.Unixtime, overlap time.Duration) error
	// ChangeDefaultAlgorithmAt schedules a change of DefaultAlg to take
	// effect at the given time.
	ChangeDefaultAlgorithmAt(alg jwa.SignatureAlgorithm, effectiveAt unixtime.Unixtime) error
	GetPendingChanges() (*PendingAlgChange, *PendingDefaultChange)
}

// KMSConfig contains base configuration for a KeyManagementSystem, including
// algorithms, key length and rotation behavior.
type KMSConfig struct {
	GenerateKeys bool
	Algs         []jwa.SignatureAlgorithm
	DefaultAlg   jwa.SignatureAlgorithm
	RSAKeyLen    int
	KeyRotation  KeyRotationConfig
}

// KeyRotationConfig is a type holding configuration for key rollover / key rotation
type KeyRotationConfig struct {
	Enabled                         bool                          `yaml:"enabled" json:"enabled"`
	Interval                        duration.DurationOption       `yaml:"interval" json:"interval"`
	Overlap                         duration.DurationOption       `yaml:"overlap" json:"overlap"`
	EntityConfigurationLifetimeFunc func() (time.Duration, error) `yaml:"-" json:"-"`
}

type kmsAsVersatileSigner struct {
	kms     BasicKeyManagementSystem
	jwksFnc func() (jwx.JWKS, error)
}

func (k kmsAsVersatileSigner) Signer(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm) {
	return k.kms.GetForAlgs(algs...)
}

func (k kmsAsVersatileSigner) DefaultSigner() (crypto.Signer, jwa.SignatureAlgorithm) {
	return k.kms.GetDefault()
}

func (k kmsAsVersatileSigner) JWKS() (jwx.JWKS, error) {
	return k.jwksFnc()
}

// KMSToVersatileSignerWithJWKSFunc returns a VersatileSigner that uses the passed
// BasicKeyManagementSystem to load keys and returns the JWKS from the passed function.
func KMSToVersatileSignerWithJWKSFunc(
	kms BasicKeyManagementSystem, jwksFnc func() (jwx.JWKS, error),
) jwx.VersatileSigner {
	return kmsAsVersatileSigner{
		kms:     kms,
		jwksFnc: jwksFnc,
	}
}

// KMSToVersatileSignerWithPKStorage returns a VersatileSigner that uses the passed
// BasicKeyManagementSystem to load keys and returns the JWKS from the passed public.PublicKeyStorage.
func KMSToVersatileSignerWithPKStorage(
	kms BasicKeyManagementSystem, pkStorage public.PublicKeyStorage,
) jwx.VersatileSigner {
	return kmsAsVersatileSigner{
		kms: kms,
		jwksFnc: func() (jwx.JWKS, error) {
			list, err := pkStorage.GetValid()
			if err != nil {
				return jwx.JWKS{}, err
			}
			return list.JWKS()
		},
	}
}

// Shared rotation helpers to reduce duplication across KMS implementations.

// earliestFutureNbfForAlg returns the earliest NotBefore among valid, non-revoked
// keys for the given algorithm, that are in the future relative to now.
func earliestFutureNbfForAlg(pkStorage public.PublicKeyStorage, alg jwa.SignatureAlgorithm, now time.Time) (
	time.Time, bool, error,
) {
	validPKs, vErr := pkStorage.GetValid()
	if vErr != nil {
		return time.Time{}, false, vErr
	}
	earliestNbf := time.Time{}
	for _, pk := range validPKs {
		algI, set := pk.Key.Algorithm()
		if !set {
			continue
		}
		a, ok := algI.(jwa.SignatureAlgorithm)
		if !ok || a.String() != alg.String() {
			continue
		}
		if pk.RevokedAt != nil && !pk.RevokedAt.IsZero() && pk.RevokedAt.Before(now) {
			continue
		}
		if pk.NotBefore != nil && !pk.NotBefore.IsZero() && pk.NotBefore.After(now) {
			if earliestNbf.IsZero() || pk.NotBefore.Before(earliestNbf) {
				earliestNbf = pk.NotBefore.Time
			}
		}
	}
	return earliestNbf, !earliestNbf.IsZero(), nil
}

// shortenExpirationUntilFuture updates the expiration of current active keys so that
// they extend until the future key's NotBefore plus overlap.
func shortenExpirationUntilFuture(
	pkStorage public.PublicKeyStorage, algPKs []public.PublicKeyEntry, earliestNbf time.Time, overlap time.Duration,
	logPrefix string,
) {
	newExpForOldKey := &unixtime.Unixtime{Time: earliestNbf.Add(overlap)}
	for _, k := range algPKs {
		if k.ExpiresAt != nil && k.ExpiresAt.IsZero() || newExpForOldKey.Before(k.ExpiresAt.Time) {
			k.ExpiresAt = newExpForOldKey
			if uErr := pkStorage.Update(k.KID, k.UpdateablePublicKeyMetadata); uErr != nil {
				log.WithError(uErr).Error(logPrefix + ": automatic rotation: failed to update old key exp")
			}
		}
	}
}

// PendingAlgChange describes a scheduled algorithm set change.
type PendingAlgChange struct {
	Algs        []jwa.SignatureAlgorithm   `json:"algs"`
	EffectiveAt unixtime.Unixtime          `json:"effective_at"`
	Overlap     unixtime.DurationInSeconds `json:"overlap"`
}

// PendingDefaultChange describes a scheduled default algorithm change.
type PendingDefaultChange struct {
	Alg         jwa.SignatureAlgorithm `json:"alg"`
	EffectiveAt unixtime.Unixtime      `json:"effective_at"`
}

// scheduledState holds pending, time-based configuration changes to be applied
// by the rotation loop. Persisted as JSON next to keys to survive restarts.
type scheduledState struct {
	PendingAlgChange     *PendingAlgChange     `json:"pending_alg_change,omitempty"`
	PendingDefaultChange *PendingDefaultChange `json:"pending_default_change,omitempty"`
}
