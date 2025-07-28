package jwx

import (
	"crypto"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

type privateKeyStorage interface {
	Load(pks *jwksSlice, pksOnChange func() error) error
	GetForAlgs(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm)
	GetDefault() (crypto.Signer, jwa.SignatureAlgorithm)
	GenerateNewKeys(pks *jwksSlice, pksOnChange func() error) error
	initKeyRotation(pks *jwksSlice, pksOnChange func() error)
}
