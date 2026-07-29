package jwx

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"

	compsig "github.com/jwx-go/compsig/v4"
	ed448ext "github.com/jwx-go/ed448/v4"
	"github.com/jwx-go/es256k/v4"
	jwxmldsa "github.com/jwx-go/mldsa/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/pkg/errors"
	"github.com/zachmann/go-utils/fileutils"
)

// ReadSignerFromFile loads the private key from the passed keyfile
func ReadSignerFromFile(keyfile string, alg jwa.SignatureAlgorithm) (SigningKey, error) {
	keyFileContent, err := fileutils.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}
	return ParseSignerFromPEM(keyFileContent, alg)
}

// ParseSignerFromPEM parses a PEM-encoded private key for the given algorithm.
func ParseSignerFromPEM(data []byte, alg jwa.SignatureAlgorithm) (SigningKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}
	var sk SigningKey
	var err error
	switch alg {
	case jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512():
		sk, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case jwa.ES256(), jwa.ES384(), jwa.ES512():
		sk, err = x509.ParseECPrivateKey(block.Bytes)
	case es256k.ES256K():
		sk, err = parseSecp256k1PKCS8PrivateKey(block.Bytes)
	case jwa.EdDSA(), jwa.EdDSAEd25519():
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		var ok bool
		sk, ok = key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("not an Ed25519 Private Key")
		}
	case ed448ext.EdDSAEd448():
		key, err := parseEd448PKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		sk = key
	case jwxmldsa.MLDSA44(), jwxmldsa.MLDSA65(), jwxmldsa.MLDSA87():
		key, err := parseMLDSAPKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		sk = key
	case compsig.MLDSA44ES256(), compsig.MLDSA65ES256(), compsig.MLDSA87ES384(),
		compsig.MLDSA44Ed25519(), compsig.MLDSA65Ed25519(), compsig.MLDSA87Ed448():
		key, err := parseCompsigPKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		sk = &compsigSigningKey{sk: key}
	default:
		return nil, errors.New("unknown signing algorithm: " + alg.String())
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return sk, nil
}

// ExportSignerAsPEM encodes a SigningKey as PEM data.
func ExportSignerAsPEM(sk SigningKey) []byte {
	return exportPrivateKeyAsPem(sk)
}

func WriteSignerToFile(sk SigningKey, filePath string) error {
	pemData := exportPrivateKeyAsPem(sk)
	err := errors.WithStack(os.WriteFile(filePath, pemData, 0600))
	return err
}
