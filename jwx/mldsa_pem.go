package jwx

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

var (
	oidMLDSA44 = asn1.ObjectIdentifier{
		2,
		16,
		840,
		1,
		101,
		3,
		4,
		3,
		17,
	}
	oidMLDSA65 = asn1.ObjectIdentifier{
		2,
		16,
		840,
		1,
		101,
		3,
		4,
		3,
		18,
	}
	oidMLDSA87 = asn1.ObjectIdentifier{
		2,
		16,
		840,
		1,
		101,
		3,
		4,
		3,
		19,
	}
)

type mldsaPKCS8 struct {
	Version    int
	Algo       mldsaAlgorithmIdentifier
	PrivateKey []byte
}

type mldsaAlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

func mldsaParamsToOID(params mldsa.Parameters) (asn1.ObjectIdentifier, error) {
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

func mldsaOIDToParams(oid asn1.ObjectIdentifier) (mldsa.Parameters, error) {
	switch {
	case oid.Equal(oidMLDSA44):
		return mldsa.MLDSA44(), nil
	case oid.Equal(oidMLDSA65):
		return mldsa.MLDSA65(), nil
	case oid.Equal(oidMLDSA87):
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, fmt.Errorf("not an ML-DSA key, got algorithm OID %s", oid)
	}
}

// marshalMLDSAPKCS8PrivateKey produces the RFC 9935 seed-only PKCS#8 encoding
// used by crypto/x509 (inner IMPLICIT [0] OCTET STRING wrapping the seed),
// which is interoperable with OpenSSL.
func marshalMLDSAPKCS8PrivateKey(key *mldsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

// parseMLDSAPKCS8PrivateKey accepts both ML-DSA PKCS#8 private-key encodings:
//
//   - the RFC 9935 seed-only form used by crypto/x509 and OpenSSL: the inner
//     PrivateKey BIT-wrapping is an IMPLICIT [0] OCTET STRING (tag 0x80)
//     containing the raw seed;
//   - the legacy form written by earlier versions of this library: an
//     OCTET STRING (tag 0x04) wrapping an inner OCTET STRING containing the
//     raw seed.
//
// Legacy keys keep loading; new keys are written in the interoperable format.
func parseMLDSAPKCS8PrivateKey(der []byte) (*mldsa.PrivateKey, error) {
	var key mldsaPKCS8
	if _, err := asn1.Unmarshal(der, &key); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8: %w", err)
	}

	params, err := mldsaOIDToParams(key.Algo.Algorithm)
	if err != nil {
		return nil, err
	}

	switch key.PrivateKey[0] {
	case 0x80: // RFC 9935 seed-only: IMPLICIT [0] OCTET STRING over the raw seed
		if len(key.PrivateKey) != 2+mldsa.PrivateKeySize {
			return nil, fmt.Errorf(
				"mldsa: invalid private key length %d (expected %d)",
				len(key.PrivateKey), 2+mldsa.PrivateKeySize,
			)
		}
		return mldsa.NewPrivateKey(params, key.PrivateKey[2:])
	case 0x04: // legacy form: OCTET STRING wrapping an inner OCTET STRING with the seed
		var seed []byte
		if _, err := asn1.Unmarshal(key.PrivateKey, &seed); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA seed: %w", err)
		}
		if len(seed) != mldsa.PrivateKeySize {
			return nil, fmt.Errorf(
				"mldsa: invalid seed length %d (expected %d)", len(seed), mldsa.PrivateKeySize,
			)
		}
		return mldsa.NewPrivateKey(params, seed)
	case 0x30: // SEQUENCE: seed and expanded key; the expanded part is redundant
		var both struct {
			Seed        []byte `asn1:"tag:0,implicit"`
			ExpandedKey []byte
		}
		if _, err := asn1.Unmarshal(key.PrivateKey, &both); err != nil {
			return nil, fmt.Errorf("failed to parse ML-DSA seed+expanded key: %w", err)
		}
		if len(both.Seed) != mldsa.PrivateKeySize {
			return nil, fmt.Errorf(
				"mldsa: invalid seed length %d (expected %d)",
				len(both.Seed), mldsa.PrivateKeySize,
			)
		}
		return mldsa.NewPrivateKey(params, both.Seed)
	default:
		return nil, fmt.Errorf("mldsa: unsupported ML-DSA private key encoding tag %02x", key.PrivateKey[0])
	}
}

func exportMLDSAPrivateKeyAsPem(key *mldsa.PrivateKey) []byte {
	der, err := marshalMLDSAPKCS8PrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		},
	)
}

// ParseMLDSAPrivateKeyFromPEM parses a PEM-encoded ML-DSA private key. Both the
// current interoperable seed-only encoding (crypto/x509, OpenSSL) and the
// legacy encoding written by earlier versions of this library are accepted.
func ParseMLDSAPrivateKeyFromPEM(data []byte) (*mldsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data")
	}
	return parseMLDSAPKCS8PrivateKey(block.Bytes)
}

// ExportMLDSAPrivateKeyAsPem encodes an ML-DSA private key as a PEM block of
// type "PRIVATE KEY" using the RFC 9935 seed-only PKCS#8 encoding, which is
// interoperable with OpenSSL.
func ExportMLDSAPrivateKeyAsPem(key *mldsa.PrivateKey) ([]byte, error) {
	der, err := marshalMLDSAPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		},
	), nil
}

// ConvertMLDSAPEM re-encodes a PEM-encoded ML-DSA private key in the current
// interoperable RFC 9935 seed-only PKCS#8 encoding. It is the migration tool
// for private keys written by earlier versions of this library (legacy
// OCTET-STRING-wrapped seed encoding): pass the old PEM content and store the
// returned PEM content in place of it. The parsed key is identical; only the
// encoding changes.
func ConvertMLDSAPEM(data []byte) ([]byte, error) {
	key, err := ParseMLDSAPrivateKeyFromPEM(data)
	if err != nil {
		return nil, err
	}
	return ExportMLDSAPrivateKeyAsPem(key)
}
