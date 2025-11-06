package kms

import (
	"crypto"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/zachmann/go-utils/duration"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/public"
)

type nbfMode int

const (
	nbfModeNow nbfMode = iota
	nbfModeNext
)

// BasicKeyManagementSystem provides methods to load keys and retrieve
// a default or algorithm-specific signer.
type BasicKeyManagementSystem interface {
	Load() error
	GetForAlgs(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm)
	GetDefault() (crypto.Signer, jwa.SignatureAlgorithm)
}

// KeyManagementSystem extends BasicKeyManagementSystem with rotation and
// automatic rotation controls.
type KeyManagementSystem interface {
	BasicKeyManagementSystem
	RotateKey(kid string, revoked bool, reason string) error
	RotateAllKeys(revoked bool, reason string) error
	StartAutomaticRotation() error
	StopAutomaticRotation()
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
	Enabled                         bool                          `yaml:"enabled"`
	Interval                        duration.DurationOption       `yaml:"interval"`
	Overlap                         duration.DurationOption       `yaml:"overlap"`
	EntityConfigurationLifetimeFunc func() (time.Duration, error) `yaml:"-"`
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
func KMSToVersatileSignerWithPKStorage(kms BasicKeyManagementSystem, pkStorage public.PublicKeyStorage) jwx.
	VersatileSigner {
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
