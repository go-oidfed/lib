package jwx

import (
	"crypto"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zachmann/go-utils/duration"
)

// Constants for TypeIDs used in a KeyStorage
const (
	KeyStorageTypeFederation = "federation"
	KeyStorageTypeOIDC       = "oidc"
)

// NewKeyStorage creates a new KeyStorage for the passed KeyStorageConfigs at the passed directory
func NewKeyStorage(keyDir string, conf map[string]KeyStorageConfig) (*KeyStorage, error) {
	ks := &KeyStorage{
		public:  make(aggregatedPublicKeyStorage),
		private: make(map[string]privateKeyStorage),
		keyDir:  keyDir,
	}
	for t, cfg := range conf {
		var sks privateKeyStorage
		if cfg.Algorithm != "" {
			// single alg
			alg, ok := jwa.LookupSignatureAlgorithm(cfg.Algorithm)
			if !ok {
				return nil, errors.Errorf("unknown algorithm '%s'", cfg.Algorithm)
			}
			sks = &privateKeyStorageSingleAlg{
				typeID:    t,
				alg:       alg,
				rollover:  cfg.RolloverConf,
				rsaKeyLen: cfg.RSAKeyLen,
				keyDir:    keyDir,
			}
		} else {
			// multi alg
			var algs []jwa.SignatureAlgorithm
			if len(algs) == 0 {
				algs = supportedAlgs
			} else {
				for _, a := range cfg.Algorithms {
					alg, ok := jwa.LookupSignatureAlgorithm(a)
					if !ok {
						return nil, errors.Errorf("unknown algorithm '%s'", a)
					}
					algs = append(algs, alg)
				}
			}
			sksma := &privateKeyStorageMultiAlg{
				typeID:    t,
				algs:      algs,
				rollover:  cfg.RolloverConf,
				rsaKeyLen: cfg.RSAKeyLen,
				keyDir:    keyDir,
			}
			if a := cfg.DefaultAlgorithm; a != "" {
				defaultAlg, ok := jwa.LookupSignatureAlgorithm(a)
				if !ok {
					return nil, errors.Errorf("unknown default algorithm '%s'", a)
				}
				sksma.defaultAlg = defaultAlg
			}
			sks = sksma
		}
		ks.private[t] = sks
		ks.public[t] = &pkCollection{
			NumberOfOldKeysKeptInJWKS: cfg.RolloverConf.NumberOfOldKeysKeptInJWKS,
			KeepHistory:               cfg.RolloverConf.KeepHistory,
		}
	}
	return ks, nil
}

// KeyStorage manages public and private signing keys for multiple typeIds (e.g. federation and oidc),
// it handles loading and writing keys to disk and can also handle key rotation.
type KeyStorage struct {
	public  aggregatedPublicKeyStorage
	private map[string]privateKeyStorage
	keyDir  string
}

// KeyStorageConfig is a type holding the configuration for keys for a protocol.
// If Algorithm is set, this implies that a single singing algorithm is supported,
// otherwise multiple algorithms are supported, even if Algorithms is not set (
// since in that case all supported algorithms should be supported)
type KeyStorageConfig struct {
	Algorithm        string       `yaml:"alg"`
	Algorithms       []string     `yaml:"algs"`
	DefaultAlgorithm string       `yaml:"default_alg"`
	RSAKeyLen        int          `yaml:"rsa_key_len"`
	RolloverConf     RolloverConf `yaml:"automatic_key_rollover"`
}

// RolloverConf is a type holding configuration for key rollover / key rotation
type RolloverConf struct {
	Enabled                   bool                    `yaml:"enabled"`
	Interval                  duration.DurationOption `yaml:"interval"`
	NumberOfOldKeysKeptInJWKS int                     `yaml:"old_keys_kept_in_jwks"`
	KeepHistory               bool                    `yaml:"keep_history"`
}

// JWKS returns the jwks.JWKS containing all public keys for the passed storageType
func (ks KeyStorage) JWKS(storageType string) JWKS {
	sets, ok := ks.public[storageType]
	if !ok || sets == nil || len(sets.jwks) == 0 {
		return JWKS{}
	}
	final := NewJWKS()
	for _, set := range sets.jwks {
		for i := range set.Len() {
			k, _ := set.Key(i)
			if err := final.AddKey(k); err != nil {
				log.Error(err.Error())
			}
		}
	}
	return final
}

// History returns the jwks history for the passed storageType
func (ks KeyStorage) History(storageType string) JWKS {
	pks, ok := ks.public[storageType]
	if !ok {
		return zeroJWKS
	}
	return pks.history
}

// Signer takes a list of acceptable signature algorithms and returns a
// usable crypto.Signer or nil as well as the corresponding
// jwa.SignatureAlgorithm for the passed storageType
func (ks KeyStorage) Signer(storageType string, algs ...string) (crypto.Signer, jwa.SignatureAlgorithm) {
	sks, ok := ks.private[storageType]
	if !ok {
		return nil, jwa.SignatureAlgorithm{}
	}
	return sks.GetForAlgs(algs...)
}

// DefaultSigner returns a crypto.Signer and the corresponding jwa.SignatureAlgorithm for the passed storageType
func (ks KeyStorage) DefaultSigner(storageType string) (crypto.Signer, jwa.SignatureAlgorithm) {
	sks, ok := ks.private[storageType]
	if !ok {
		return nil, jwa.SignatureAlgorithm{}
	}
	return sks.GetDefault()
}

// FederationJWKS returns the jwks.JWKS containing all public keys for the KeyStorageTypeFederation storageTypeID
func (ks KeyStorage) FederationJWKS() JWKS {
	return ks.JWKS(KeyStorageTypeFederation)
}

// OIDCJWKS returns the jwks.JWKS containing all public keys for the KeyStorageTypeOIDC storageTypeID
func (ks KeyStorage) OIDCJWKS() JWKS {
	return ks.JWKS(KeyStorageTypeOIDC)
}

// FederationSigner returns the crypto.Signer and the corresponding jwa.SignatureAlgorithm
// for the KeyStorageTypeFederation storageTypeID
func (ks KeyStorage) FederationSigner() (crypto.Signer, jwa.SignatureAlgorithm) {
	return ks.DefaultSigner(KeyStorageTypeFederation)
}

// Load loads the KeyStorage from disk and if enabled schedules key rotation.
func (ks *KeyStorage) Load() error {
	if err := ks.public.Load(ks.keyDir); err != nil {
		return err
	}

	var mutex sync.Mutex

	for typeID, sks := range ks.private {
		pks, found := ks.public[typeID]
		if !found {
			pks = &pkCollection{}
			ks.public[typeID] = pks
		}
		if err := sks.Load(
			pks, func() error {
				mutex.Lock()
				defer mutex.Unlock()
				return ks.Save()
			},
		); err != nil {
			return err
		}
	}
	return nil
}

// Save saves the KeyStorage to disk
func (ks KeyStorage) Save() error {
	return ks.public.Save(ks.keyDir)
}

// SubStorage returns a VersatileSigner for the passed storageTypeID
func (ks *KeyStorage) SubStorage(typeID string) VersatileSigner {
	return substorage{
		ks:     ks,
		typeID: typeID,
	}
}

// Federation returns a VersatileSigner for the KeyStorageTypeFederation
func (ks *KeyStorage) Federation() VersatileSigner {
	return ks.SubStorage(KeyStorageTypeFederation)
}

// OIDC returns a VersatileSigner for the KeyStorageTypeOIDC
func (ks *KeyStorage) OIDC() VersatileSigner {
	return ks.SubStorage(KeyStorageTypeOIDC)
}

// substorage is a type related to a KeyStorage and implements the VersatileSigner interface for a storageTypeID
type substorage struct {
	ks     *KeyStorage
	typeID string
}

// Signer takes a list of acceptable signature algorithms and returns a
// usable crypto.Signer or nil as well as the corresponding
// jwa.SignatureAlgorithm
func (s substorage) Signer(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm) {
	return s.ks.Signer(s.typeID, algs...)
}

// DefaultSigner returns a crypto.Signer and the corresponding jwa.SignatureAlgorithm
func (s substorage) DefaultSigner() (crypto.Signer, jwa.SignatureAlgorithm) {
	return s.ks.DefaultSigner(s.typeID)
}

// JWKS returns the jwks.JWKS containing all public keys of this VersatileSigner
func (s substorage) JWKS() JWKS {
	return s.ks.JWKS(s.typeID)
}
