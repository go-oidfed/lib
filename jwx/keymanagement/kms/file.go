package kms

import (
	"crypto"

	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/go-oidfed/lib/jwx"
)

// SingleSigningKeyFile implements BasicKeyManagementSystem for a single
// configured signing key stored in a PEM file on disk. It exposes a signer
// and its algorithm without any rotation behavior.
type SingleSigningKeyFile struct {
	// Alg is the single configured signature algorithm for this signer.
	Alg jwa.SignatureAlgorithm
	// Path is the filesystem path to the PEM-encoded private key.
	Path string

	signer crypto.Signer
}

// GetDefaultAlg returns the configured algorithm.
func (s *SingleSigningKeyFile) GetDefaultAlg() jwa.SignatureAlgorithm {
	return s.Alg
}

// GetAlgs returns the configured algorithm.
func (s *SingleSigningKeyFile) GetAlgs() []jwa.SignatureAlgorithm {
	return []jwa.SignatureAlgorithm{s.Alg}
}

// Load loads the signer from the configured file path.
func (s *SingleSigningKeyFile) Load() error {
	signer, err := jwx.ReadSignerFromFile(s.Path, s.Alg)
	if err != nil {
		return err
	}
	s.signer = signer
	return nil
}

// GetDefault returns the configured signer and its algorithm.
func (s *SingleSigningKeyFile) GetDefault() (crypto.Signer, jwa.SignatureAlgorithm) {
	if s.signer == nil {
		return nil, jwa.SignatureAlgorithm{}
	}
	return s.signer, s.Alg
}

// GetForAlgs returns the signer if the requested algorithms include the
// configured algorithm; otherwise nil.
func (s *SingleSigningKeyFile) GetForAlgs(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm) {
	if s.signer == nil {
		return nil, jwa.SignatureAlgorithm{}
	}
	want := s.Alg.String()
	for _, a := range algs {
		if a == want {
			return s.signer, s.Alg
		}
	}
	return nil, jwa.SignatureAlgorithm{}
}
