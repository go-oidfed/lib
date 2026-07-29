package jwx

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	compsig "github.com/jwx-go/compsig/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

// Composite signature OIDs from draft-ietf-lamps-pq-composite-sigs-04.
// Base arc: 2.16.840.1.114027.80.8.1
var (
	oidMLDSA44ES256   = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 8, 1, 63}
	oidMLDSA65ES256   = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 8, 1, 68}
	oidMLDSA87ES384   = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 8, 1, 72}
	oidMLDSA44Ed25519 = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 8, 1, 62}
	oidMLDSA65Ed25519 = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 8, 1, 71}
	oidMLDSA87Ed448   = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 8, 1, 74}
)

type compsigPKCS8 struct {
	Version    int
	Algo       compsigAlgorithmIdentifier
	PrivateKey []byte
}

type compsigAlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

func compsigAlgToOID(alg jwa.SignatureAlgorithm) (asn1.ObjectIdentifier, error) {
	switch alg.String() {
	case compsig.MLDSA44ES256().String():
		return oidMLDSA44ES256, nil
	case compsig.MLDSA65ES256().String():
		return oidMLDSA65ES256, nil
	case compsig.MLDSA87ES384().String():
		return oidMLDSA87ES384, nil
	case compsig.MLDSA44Ed25519().String():
		return oidMLDSA44Ed25519, nil
	case compsig.MLDSA65Ed25519().String():
		return oidMLDSA65Ed25519, nil
	case compsig.MLDSA87Ed448().String():
		return oidMLDSA87Ed448, nil
	default:
		return nil, fmt.Errorf("compsig: unknown algorithm %s", alg.String())
	}
}

func compsigOIDToAlg(oid asn1.ObjectIdentifier) (jwa.SignatureAlgorithm, error) {
	switch {
	case oid.Equal(oidMLDSA44ES256):
		return compsig.MLDSA44ES256(), nil
	case oid.Equal(oidMLDSA65ES256):
		return compsig.MLDSA65ES256(), nil
	case oid.Equal(oidMLDSA87ES384):
		return compsig.MLDSA87ES384(), nil
	case oid.Equal(oidMLDSA44Ed25519):
		return compsig.MLDSA44Ed25519(), nil
	case oid.Equal(oidMLDSA65Ed25519):
		return compsig.MLDSA65Ed25519(), nil
	case oid.Equal(oidMLDSA87Ed448):
		return compsig.MLDSA87Ed448(), nil
	default:
		return jwa.SignatureAlgorithm{}, fmt.Errorf("not a composite signature key, got algorithm OID %s", oid)
	}
}

func marshalCompsigPKCS8PrivateKey(key *compsig.PrivateKey) ([]byte, error) {
	raw, err := key.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal composite private key: %w", err)
	}

	oid, err := compsigAlgToOID(key.Algorithm())
	if err != nil {
		return nil, err
	}

	innerKey, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal composite key data: %w", err)
	}

	pkcs8Key := compsigPKCS8{
		Version: 0,
		Algo: compsigAlgorithmIdentifier{
			Algorithm: oid,
		},
		PrivateKey: innerKey,
	}

	return asn1.Marshal(pkcs8Key)
}

func parseCompsigPKCS8PrivateKey(der []byte) (*compsig.PrivateKey, error) {
	var key compsigPKCS8
	if _, err := asn1.Unmarshal(der, &key); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8: %w", err)
	}

	alg, err := compsigOIDToAlg(key.Algo.Algorithm)
	if err != nil {
		return nil, err
	}

	var raw []byte
	if _, err := asn1.Unmarshal(key.PrivateKey, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse composite key data: %w", err)
	}

	return compsig.NewPrivateKey(alg, raw)
}

func exportCompsigPrivateKeyAsPem(key *compsig.PrivateKey) []byte {
	der, err := marshalCompsigPKCS8PrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}
