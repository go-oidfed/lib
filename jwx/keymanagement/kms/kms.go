package kms

import (
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/zachmann/go-utils/duration"

	log "github.com/go-oidfed/lib/internal"

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

	// defaultKeyAnnouncementLeadTime is the minimum default key announcement
	// lead time. The actual default is max(5 * EC lifetime, this value).
	defaultKeyAnnouncementLeadTime           = 24 * time.Hour
	defaultKeyAnnouncementLeadTimeMultiplier = 5.0
)

// BasicKeyManagementSystem provides methods to load keys and retrieve
// a default or algorithm-specific signer.
type BasicKeyManagementSystem interface {
	Load() error
	GetForAlgs(algs ...string) (jwx.SigningKey, jwa.SignatureAlgorithm)
	GetDefault() (jwx.SigningKey, jwa.SignatureAlgorithm)
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
	Enabled                             bool                          `yaml:"enabled" json:"enabled"`
	Interval                            duration.DurationOption       `yaml:"interval" json:"interval"`
	Overlap                             duration.DurationOption       `yaml:"overlap" json:"overlap"`
	KeyAnnouncementLeadTime             duration.DurationOption       `yaml:"key_announcement_lead_time" json:"key_announcement_lead_time"`
	KeyAnnouncementLeadTimeECMultiplier float64                       `yaml:"key_announcement_lead_time_ec_multiplier" json:"key_announcement_lead_time_ec_multiplier"`
	EntityConfigurationLifetimeFunc     func() (time.Duration, error) `yaml:"-" json:"-"`
}

// ecLifetime safely calls EntityConfigurationLifetimeFunc.
func (c KeyRotationConfig) ecLifetime() (time.Duration, error) {
	if c.EntityConfigurationLifetimeFunc == nil {
		return 0, errors.New("EntityConfigurationLifetimeFunc not set")
	}
	return c.EntityConfigurationLifetimeFunc()
}

// KeyAnnouncementLeadTimeDuration resolves the effective key announcement
// lead time — how far in advance a new key is published in the JWKS before it
// becomes the active signing key.
//
// Resolution order:
//  1. If KeyAnnouncementLeadTimeECMultiplier > 0: multiplier * EC lifetime
//  2. If KeyAnnouncementLeadTime > 0: fixed duration
//  3. Default: max(5 * EC lifetime, 24h)
//
// The result is clamped to a minimum of the EC lifetime. If the configured
// value is shorter, the EC lifetime is used instead and a warning is logged.
func (c KeyRotationConfig) KeyAnnouncementLeadTimeDuration() (time.Duration, error) {
	var leadTime time.Duration

	if c.KeyAnnouncementLeadTimeECMultiplier > 0 {
		ecLifetime, err := c.ecLifetime()
		if err != nil {
			return 0, err
		}
		leadTime = time.Duration(float64(ecLifetime) * c.KeyAnnouncementLeadTimeECMultiplier)
	} else if d := c.KeyAnnouncementLeadTime.Duration(); d > 0 {
		leadTime = d
	} else {
		ecLifetime, err := c.ecLifetime()
		if err != nil {
			leadTime = defaultKeyAnnouncementLeadTime
		} else {
			leadTime = time.Duration(defaultKeyAnnouncementLeadTimeMultiplier) * ecLifetime
			if leadTime < defaultKeyAnnouncementLeadTime {
				leadTime = defaultKeyAnnouncementLeadTime
			}
		}
	}

	if ecLifetime, err := c.ecLifetime(); err == nil && leadTime < ecLifetime {
		log.Warnf(
			"key announcement lead time (%s) is shorter than EC lifetime (%s); using EC lifetime as minimum",
			leadTime, ecLifetime,
		)
		leadTime = ecLifetime
	}

	return leadTime, nil
}

type kmsAsVersatileSigner struct {
	kms     BasicKeyManagementSystem
	jwksFnc func() (jwx.JWKS, error)
}

func (k kmsAsVersatileSigner) Signer(algs ...string) (jwx.SigningKey, jwa.SignatureAlgorithm) {
	return k.kms.GetForAlgs(algs...)
}

func (k kmsAsVersatileSigner) DefaultSigner() (jwx.SigningKey, jwa.SignatureAlgorithm) {
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
		if k.ExpiresAt == nil || k.ExpiresAt.IsZero() || newExpForOldKey.Before(k.ExpiresAt.Time) {
			k.ExpiresAt = newExpForOldKey
			if uErr := pkStorage.Update(k.KID, k.UpdateablePublicKeyMetadata); uErr != nil {
				log.Logger().Error().Err(uErr).Msg(logPrefix + ": automatic rotation: failed to update old key exp")
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

// ScheduledState holds pending, time-based configuration changes to be applied
// by the rotation loop. Persisted as JSON next to keys to survive restarts.
type ScheduledState struct {
	PendingAlgChange     *PendingAlgChange     `json:"pending_alg_change,omitempty"`
	PendingDefaultChange *PendingDefaultChange `json:"pending_default_change,omitempty"`
}

// PEMStorer defines the interface for storing and retrieving
// PEM-encoded private keys by KID
type PEMStorer interface {
	ReadPEM(kid string) ([]byte, error)
	WritePEM(kid string, data []byte) error
}

// KMSStateStorer defines the interface for persisting scheduled
// configuration changes (algorithm changes, default algorithm changes)
type KMSStateStorer interface {
	LoadScheduledState() (ScheduledState, error)
	SaveScheduledState(ScheduledState) error
}

// sortKeysByPreference returns indices of algPKs sorted by signing preference.
// Keys are ordered from most preferred to least preferred based on expiration
// and not-before times. This allows callers to try keys in order until finding
// one with a matching private key.
func sortKeysByPreference(
	algPKs []public.PublicKeyEntry, overlap time.Duration,
) []int {
	if len(algPKs) <= 1 {
		return []int{0}
	}

	nbfThreshold := time.Now().Add(-overlap / 2)
	maxExp := unixtime.Now()
	maxExpWithNbf := maxExp

	noExpIndex := -1
	maxExpIndex := -1
	maxExpWithNbfIndex := -1

	for i, it := range algPKs {
		if it.ExpiresAt == nil {
			noExpIndex = i
			continue
		}
		if it.NotBefore != nil && it.NotBefore.Before(nbfThreshold) && it.ExpiresAt.After(
			maxExpWithNbf.Time,
		) {
			maxExpWithNbf = *it.ExpiresAt
			maxExpWithNbfIndex = i

		} else if maxExpIndex == -1 && it.ExpiresAt.After(maxExp.Time) {
			maxExp = *it.ExpiresAt
			maxExpIndex = i
		}
	}

	var preferred []int
	if maxExpWithNbfIndex != -1 {
		preferred = append(preferred, maxExpWithNbfIndex)
	}
	if maxExpIndex != -1 {
		preferred = append(preferred, maxExpIndex)
	}
	if noExpIndex != -1 {
		preferred = append(preferred, noExpIndex)
	}

	for i := range algPKs {
		if i != maxExpWithNbfIndex && i != maxExpIndex && i != noExpIndex {
			preferred = append(preferred, i)
		}
	}

	return preferred
}
