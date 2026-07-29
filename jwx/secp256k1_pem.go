package jwx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	oidEC          = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp256k1   = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	secp256k1Curve = secp256k1.S256()
)

type pkcs8 struct {
	Version    int
	Algo       pkixAlgorithmIdentifier
	PrivateKey []byte
}

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type sec1ECPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"tag:0,optional,explicit"`
	PublicKey     asn1.BitString        `asn1:"tag:1,optional,explicit"`
}

func marshalSecp256k1PKCS8PrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	privBytes := key.D.FillBytes(make([]byte, 32))

	pubX, pubY := key.PublicKey.X, key.PublicKey.Y
	pubBytes := elliptic.Marshal(secp256k1Curve, pubX, pubY)

	sec1 := sec1ECPrivateKey{
		Version:    1,
		PrivateKey: privBytes,
		PublicKey: asn1.BitString{
			Bytes:     pubBytes,
			BitLength: len(pubBytes) * 8,
		},
	}
	sec1DER, err := asn1.Marshal(sec1)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SEC1 private key: %w", err)
	}

	curveOIDBytes, err := asn1.Marshal(oidSecp256k1)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secp256k1 OID: %w", err)
	}

	pkcs8Key := pkcs8{
		Version: 0,
		Algo: pkixAlgorithmIdentifier{
			Algorithm: oidEC,
			Parameters: asn1.RawValue{
				FullBytes: curveOIDBytes,
			},
		},
		PrivateKey: sec1DER,
	}

	return asn1.Marshal(pkcs8Key)
}

func parseSecp256k1PKCS8PrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	var key pkcs8
	if _, err := asn1.Unmarshal(der, &key); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8: %w", err)
	}

	if !key.Algo.Algorithm.Equal(oidEC) {
		return nil, fmt.Errorf("not an EC key, got algorithm %s", key.Algo.Algorithm)
	}

	var paramsOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(key.Algo.Parameters.FullBytes, &paramsOID); err != nil {
		return nil, fmt.Errorf("failed to parse curve OID: %w", err)
	}
	if !paramsOID.Equal(oidSecp256k1) {
		return nil, fmt.Errorf("not a secp256k1 key, got curve OID %s", paramsOID)
	}

	var sec1Key sec1ECPrivateKey
	if _, err := asn1.Unmarshal(key.PrivateKey, &sec1Key); err != nil {
		return nil, fmt.Errorf("failed to parse SEC1 private key: %w", err)
	}

	d := new(big.Int).SetBytes(sec1Key.PrivateKey)
	x, y := secp256k1Curve.ScalarBaseMult(sec1Key.PrivateKey)

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: secp256k1Curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}

func exportSecp256k1PrivateKeyAsPem(key *ecdsa.PrivateKey) []byte {
	der, err := marshalSecp256k1PKCS8PrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}
