package jwx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/unixtime"
)

// generatePrivateKey generates a cryptographic private key with the passed properties
func generatePrivateKey(alg jwa.SignatureAlgorithm, rsaKeyLen int) (
	sk crypto.Signer, err error,
) {
	switch alg {
	case jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512():
		if rsaKeyLen <= 0 {
			return nil, errors.Errorf("%s specified, but no valid RSA key len", alg)
		}
		sk, err = rsa.GenerateKey(rand.Reader, rsaKeyLen)
	case jwa.ES256():
		sk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jwa.ES384():
		sk, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case jwa.ES512():
		sk, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case jwa.EdDSA():
		_, sk, err = ed25519.GenerateKey(rand.Reader)
	default:
		err = errors.Errorf("unknown signing algorithm '%s'", alg)
		return
	}
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	return
}

// exportPrivateKeyAsPem exports the private key
func exportPrivateKeyAsPem(sk crypto.Signer) []byte {
	switch sk := sk.(type) {
	case *rsa.PrivateKey:
		return exportRSAPrivateKeyAsPem(sk)
	case *ecdsa.PrivateKey:
		return exportECPrivateKeyAsPem(sk)
	case ed25519.PrivateKey:
		return exportEDDSAPrivateKeyAsPem(sk)
	default:
		return nil
	}
}

func exportECPrivateKeyAsPem(privkey *ecdsa.PrivateKey) []byte {
	privkeyBytes, _ := x509.MarshalECPrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return privkeyPem
}

func exportRSAPrivateKeyAsPem(privkey *rsa.PrivateKey) []byte {
	privkeyBytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return privkeyPem
}

func exportEDDSAPrivateKeyAsPem(privkey ed25519.PrivateKey) []byte {
	privkeyBytes, _ := x509.MarshalPKCS8PrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return privkeyPem
}

type keyLifetimeConf struct {
	NowIssued bool
	Expires   bool
	Lifetime  time.Duration
	Nbf       *unixtime.Unixtime
}

func signerToPublicJWK(sk crypto.Signer, alg jwa.SignatureAlgorithm, lifetimeConf keyLifetimeConf) (jwk.Key, error) {
	pk, err := jwk.PublicKeyOf(sk.Public())
	if err != nil {
		return nil, err
	}
	if err = jwk.AssignKeyID(pk); err != nil {
		return nil, errors.WithStack(err)
	}
	if err = pk.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, errors.WithStack(err)
	}
	if err = pk.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, errors.WithStack(err)
	}
	now := unixtime.Now()
	if lifetimeConf.NowIssued {
		if err = pk.Set("iat", now); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	if lifetimeConf.Expires {
		exp := unixtime.Unixtime{Time: now.Add(lifetimeConf.Lifetime)}
		if lifetimeConf.Nbf != nil && lifetimeConf.Nbf.After(now.Time) {
			if err = errors.WithStack(pk.Set("nbf", lifetimeConf.Nbf)); err != nil {
				return nil, err
			}
			exp = unixtime.Unixtime{Time: lifetimeConf.Nbf.Add(lifetimeConf.Lifetime)}
		}
		if err = errors.WithStack(pk.Set("exp", exp)); err != nil {
			return nil, err
		}
	}
	return pk, nil
}

// generatePrivateKey generates a cryptographic private key with the passed
// properties and returns the corresponding public key as a jwk.Key
func generateKeyPair(alg jwa.SignatureAlgorithm, rsaKeyLen int, lifetimeConf keyLifetimeConf) (
	sk crypto.Signer, pk jwk.Key, err error,
) {
	sk, err = generatePrivateKey(alg, rsaKeyLen)
	if err != nil {
		return
	}
	lifetimeConf.NowIssued = true
	pk, err = signerToPublicJWK(sk, alg, lifetimeConf)
	return
}
