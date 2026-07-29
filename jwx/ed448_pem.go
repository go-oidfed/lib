package jwx

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	ed448 "github.com/cloudflare/circl/sign/ed448"
)

var oidEd448 = asn1.ObjectIdentifier{1, 3, 101, 113}

type ed448PKCS8 struct {
	Version    int
	Algo       ed448AlgorithmIdentifier
	PrivateKey []byte
}

type ed448AlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

func marshalEd448PKCS8PrivateKey(key ed448.PrivateKey) ([]byte, error) {
	if len(key) != ed448.PrivateKeySize {
		return nil, fmt.Errorf("ed448: invalid private key length %d (expected %d)", len(key), ed448.PrivateKeySize)
	}
	seed := key.Seed()

	// The PrivateKey field in PKCS#8 is an OCTET STRING containing the
	// DER-encoded private key. For Ed448 (like Ed25519), the inner
	// encoding is an OCTET STRING wrapping the raw seed bytes.
	innerKey, err := asn1.Marshal(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Ed448 seed: %w", err)
	}

	pkcs8Key := ed448PKCS8{
		Version: 0,
		Algo: ed448AlgorithmIdentifier{
			Algorithm: oidEd448,
		},
		PrivateKey: innerKey,
	}

	return asn1.Marshal(pkcs8Key)
}

func parseEd448PKCS8PrivateKey(der []byte) (ed448.PrivateKey, error) {
	var key ed448PKCS8
	if _, err := asn1.Unmarshal(der, &key); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8: %w", err)
	}

	if !key.Algo.Algorithm.Equal(oidEd448) {
		return nil, fmt.Errorf("not an Ed448 key, got algorithm OID %s", key.Algo.Algorithm)
	}

	var seed []byte
	if _, err := asn1.Unmarshal(key.PrivateKey, &seed); err != nil {
		return nil, fmt.Errorf("failed to parse Ed448 seed: %w", err)
	}

	if len(seed) != ed448.SeedSize {
		return nil, fmt.Errorf("ed448: invalid seed length %d (expected %d)", len(seed), ed448.SeedSize)
	}

	return ed448.NewKeyFromSeed(seed), nil
}

func exportEd448PrivateKeyAsPem(key ed448.PrivateKey) []byte {
	der, err := marshalEd448PKCS8PrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}
