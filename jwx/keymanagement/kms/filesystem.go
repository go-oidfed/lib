package kms

import (
	"encoding/json"
	"os"
	"path/filepath"

	log "github.com/go-oidfed/lib/internal"

	"github.com/lestrrat-go/jwx/v3/jwa"

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

	pemStorer := &FilesystemPEMStorage{Dir: config.Dir}
	stateStorer := &FilesystemStateStorer{Dir: config.Dir}

	kms := NewPEMStorageKMS(
		config.KMSConfig,
		pemStorer,
		stateStorer,
		pks,
	)
	if err := kms.Load(); err != nil {
		log.WithError(err).Error("Failed to load PEMStorageKMS")
		return nil
	}

	return &FilesystemKMS{PEMStorageKMS: kms}
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

	pemStorer := &FilesystemPEMStorage{Dir: config.Dir}
	stateStorer := &FilesystemStateStorer{Dir: config.Dir}

	kms := NewPEMStorageKMS(
		config.KMSConfig,
		pemStorer,
		stateStorer,
		pks,
	)
	if err := kms.Load(); err != nil {
		return nil, err
	}

	return &FilesystemKMS{PEMStorageKMS: kms}, nil
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
	*PEMStorageKMS
}

// FilesystemPEMStorage implements PEMStorer using files
type FilesystemPEMStorage struct {
	Dir string
}

func (fps *FilesystemPEMStorage) ReadPEM(kid string) ([]byte, error) {
	return os.ReadFile(fps.keyFilePath(kid))
}

func (fps *FilesystemPEMStorage) WritePEM(kid string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(fps.keyFilePath(kid)), 0o700); err != nil {
		return err
	}
	return os.WriteFile(fps.keyFilePath(kid), data, 0600)
}

func (fps *FilesystemPEMStorage) keyFilePath(kid string) string {
	return filepath.Join(fps.Dir, kid+".pem")
}

// FilesystemStateStorer implements KMahlSStateStorer using files
type FilesystemStateStorer struct {
	Dir string
}

func (fss *FilesystemStateStorer) stateFilePath() string {
	return filepath.Join(fss.Dir, "kms_state.json")
}

func (fss *FilesystemStateStorer) LoadScheduledState() (scheduledState, error) {
	f := fss.stateFilePath()
	b, err := os.ReadFile(f)
	if err != nil {
		if os.IsNotExist(err) {
			return scheduledState{}, nil
		}
		return scheduledState{}, err
	}
	if len(b) == 0 {
		return scheduledState{}, nil
	}
	var st scheduledState
	err = json.Unmarshal(b, &st)
	return st, err
}

func (fss *FilesystemStateStorer) SaveScheduledState(st scheduledState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	p := fss.stateFilePath()
	if err = os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0600)
}

// NewFilesystemKMSFromBasic creates a new FilesystemKMS initialized from an existing
// BasicKeyManagementSystem and persists private keys for the configured algorithms
// into the filesystem at the configured directory.
func NewFilesystemKMSFromBasic(
	src BasicKeyManagementSystem,
	config FilesystemKMSConfig,
	pks public.PublicKeyStorage,
) (KeyManagementSystem, error) {
	pemStorer := &FilesystemPEMStorage{Dir: config.Dir}
	stateStorer := &FilesystemStateStorer{Dir: config.Dir}

	kms := NewPEMStorageKMS(
		config.KMSConfig,
		pemStorer,
		stateStorer,
		pks,
	)

	if err := pks.Load(); err != nil {
		return nil, err
	}

	for _, alg := range config.Algs {
		signer, usedAlg := src.GetForAlgs(alg.String())
		if signer == nil || usedAlg.String() == "" {
			continue
		}
		pk, kid, err := jwx.SignerToPublicJWK(signer, usedAlg)
		if err != nil {
			return nil, err
		}

		pemData, err := writeSignerToPEM(signer)
		if err != nil {
			return nil, err
		}
		if err = pemStorer.WritePEM(kid, pemData); err != nil {
			return nil, err
		}

		kms.signers[kid] = signer

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

	if err := kms.Load(); err != nil {
		log.WithError(err).Warn("NewFilesystemKMSFromBasic: Load encountered issues after migration")
	}

	return &FilesystemKMS{PEMStorageKMS: kms}, nil
}
