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

func generateStoreAndSetNextPrivateKey(
	pks *pkCollection, alg jwa.SignatureAlgorithm, rsaKeyLen int, lifetimeConf keyLifetimeConf, filePath string,
	newPKSet bool,
) (crypto.Signer, error) {
	skFuture, pkFuture, err := generateKeyPair(
		alg, rsaKeyLen, lifetimeConf,
	)
	if err != nil {
		return nil, err
	}
	if err = writeSignerToFile(skFuture, filePath); err != nil {
		return nil, err
	}
	if newPKSet {
		pkSet := NewJWKS()
		_ = pkSet.AddKey(pkFuture)
		pks.setNextJWKS(pkSet)
	} else {
		pks.addNextJWK(pkFuture)
	}
	return skFuture, nil
}
