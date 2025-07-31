package jwx

import (
	"crypto"
	"slices"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

// SingleKeyStorage is a type implementing the oidfed.VersatileSigner interface but only
// uses a single key / alg
type SingleKeyStorage struct {
	sk  crypto.Signer
	alg jwa.SignatureAlgorithm
}

// NewSingleKeyVersatileSigner creates a new SingleKeyStorage
func NewSingleKeyVersatileSigner(sk crypto.Signer, alg jwa.SignatureAlgorithm) SingleKeyStorage {
	return SingleKeyStorage{
		sk:  sk,
		alg: alg,
	}
}

// Signer takes a list of acceptable signature algorithms and returns a
// usable crypto.Signer or nil as well as the corresponding
// jwa.SignatureAlgorithm
func (s SingleKeyStorage) Signer(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm) {
	if slices.Contains(algs, s.alg.String()) {
		return s.sk, s.alg
	}
	return nil, jwa.SignatureAlgorithm{}
}

// DefaultSigner returns a crypto.Signer and the corresponding jwa.SignatureAlgorithm
func (s SingleKeyStorage) DefaultSigner() (crypto.Signer, jwa.SignatureAlgorithm) {
	return s.sk, s.alg
}

// JWKS returns the jwks.JWKS containing all public keys of this VersatileSigner
func (s SingleKeyStorage) JWKS() JWKS {
	jwks, _ := KeyToJWKS(s.sk.Public(), jwa.ES512())
	return jwks
}
