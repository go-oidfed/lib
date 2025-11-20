package jwx

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/pkg/errors"
	"github.com/zachmann/go-utils/fileutils"
)

// ReadSignerFromFile loads the private key from the passed keyfile
func ReadSignerFromFile(keyfile string, alg jwa.SignatureAlgorithm) (crypto.Signer, error) {
	keyFileContent, err := fileutils.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyFileContent)
	var sk crypto.Signer
	switch alg {
	case jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512():
		sk, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case jwa.ES256(), jwa.ES384(), jwa.ES512():
		sk, err = x509.ParseECPrivateKey(block.Bytes)
	case jwa.EdDSA():
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		var ok bool
		sk, ok = key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("not an Ed25519 Private Key")
		}
	default:
		return nil, errors.New("unknown signing algorithm: " + alg.String())
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return sk, nil
}

func WriteSignerToFile(sk crypto.Signer, filePath string) error {
	pemData := exportPrivateKeyAsPem(sk)
	err := errors.WithStack(os.WriteFile(filePath, pemData, 0600))
	return err
}
