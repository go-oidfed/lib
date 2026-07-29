package jwx

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	mldsa "filippo.io/mldsa"
)

var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

type mldsaPKCS8 struct {
	Version    int
	Algo       mldsaAlgorithmIdentifier
	PrivateKey []byte
}

type mldsaAlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

func mldsaParamsToOID(params *mldsa.Parameters) (asn1.ObjectIdentifier, error) {
	switch params {
	case mldsa.MLDSA44():
		return oidMLDSA44, nil
	case mldsa.MLDSA65():
		return oidMLDSA65, nil
	case mldsa.MLDSA87():
		return oidMLDSA87, nil
	default:
		return nil, fmt.Errorf("mldsa: unknown parameter set %s", params.String())
	}
}

func mldsaOIDToParams(oid asn1.ObjectIdentifier) (*mldsa.Parameters, error) {
	switch {
	case oid.Equal(oidMLDSA44):
		return mldsa.MLDSA44(), nil
	case oid.Equal(oidMLDSA65):
		return mldsa.MLDSA65(), nil
	case oid.Equal(oidMLDSA87):
		return mldsa.MLDSA87(), nil
	default:
		return nil, fmt.Errorf("not an ML-DSA key, got algorithm OID %s", oid)
	}
}

func marshalMLDSAPKCS8PrivateKey(key *mldsa.PrivateKey) ([]byte, error) {
	seed := key.Bytes()
	if len(seed) != mldsa.PrivateKeySize {
		return nil, fmt.Errorf("mldsa: invalid private key seed length %d (expected %d)", len(seed), mldsa.PrivateKeySize)
	}

	oid, err := mldsaParamsToOID(key.PublicKey().Parameters())
	if err != nil {
		return nil, err
	}

	innerKey, err := asn1.Marshal(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ML-DSA seed: %w", err)
	}

	pkcs8Key := mldsaPKCS8{
		Version: 0,
		Algo: mldsaAlgorithmIdentifier{
			Algorithm: oid,
		},
		PrivateKey: innerKey,
	}

	return asn1.Marshal(pkcs8Key)
}

func parseMLDSAPKCS8PrivateKey(der []byte) (*mldsa.PrivateKey, error) {
	var key mldsaPKCS8
	if _, err := asn1.Unmarshal(der, &key); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8: %w", err)
	}

	params, err := mldsaOIDToParams(key.Algo.Algorithm)
	if err != nil {
		return nil, err
	}

	var seed []byte
	if _, err := asn1.Unmarshal(key.PrivateKey, &seed); err != nil {
		return nil, fmt.Errorf("failed to parse ML-DSA seed: %w", err)
	}

	if len(seed) != mldsa.PrivateKeySize {
		return nil, fmt.Errorf("mldsa: invalid seed length %d (expected %d)", len(seed), mldsa.PrivateKeySize)
	}

	return mldsa.NewPrivateKey(params, seed)
}

func exportMLDSAPrivateKeyAsPem(key *mldsa.PrivateKey) []byte {
	der, err := marshalMLDSAPKCS8PrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}
