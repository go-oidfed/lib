package jwx

import (
	"crypto"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

type privateKeyStorage interface {
	Load(pks *pkCollection, pksOnChange func() error) error
	GetForAlgs(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm)
	GetDefault() (crypto.Signer, jwa.SignatureAlgorithm)
	GenerateNewKeys(pks *pkCollection, pksOnChange func() error) error
	initKeyRotation(pks *pkCollection, pksOnChange func() error)
}
