package jwx

import (
	"crypto"
	"slices"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

// SingleKeySigner is a type implementing the oidfed.VersatileSigner interface but only
// uses a single key / alg
type SingleKeySigner struct {
	sk  crypto.Signer
	alg jwa.SignatureAlgorithm
}

// NewSingleKeyVersatileSigner creates a new SingleKeySigner
func NewSingleKeyVersatileSigner(sk crypto.Signer, alg jwa.SignatureAlgorithm) SingleKeySigner {
	return SingleKeySigner{
		sk:  sk,
		alg: alg,
	}
}

// Signer takes a list of acceptable signature algorithms and returns a
// usable crypto.Signer or nil as well as the corresponding
// jwa.SignatureAlgorithm
func (s SingleKeySigner) Signer(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm) {
	if slices.Contains(algs, s.alg.String()) {
		return s.sk, s.alg
	}
	return nil, jwa.SignatureAlgorithm{}
}

// DefaultSigner returns a crypto.Signer and the corresponding jwa.SignatureAlgorithm
func (s SingleKeySigner) DefaultSigner() (crypto.Signer, jwa.SignatureAlgorithm) {
	return s.sk, s.alg
}

// JWKS returns the jwks.JWKS containing all public keys of this VersatileSigner
func (s SingleKeySigner) JWKS() (JWKS, error) {
	return KeyToJWKS(s.sk.Public(), jwa.ES512())
}
