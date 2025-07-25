package keystorage

import (
	"crypto"

	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/go-oidfed/lib/jwks"
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

// Signer returns a crypto.Signer usable for the passed jwa.SignatureAlgorithm or nil
func (s SingleKeyStorage) Signer(jwa.SignatureAlgorithm) crypto.Signer {
	return s.sk
}

// JWKS returns the jwks.JWKS containing all public keys of this VersatileSigner
func (s SingleKeyStorage) JWKS() jwks.JWKS {
	return jwks.KeyToJWKS(s.sk.Public(), jwa.ES512())
}
