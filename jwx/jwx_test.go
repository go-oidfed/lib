package jwx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"io"
	"strings"
	"testing"
	"time"

	"filippo.io/mldsa"
	"github.com/cloudflare/circl/sign/ed448"
	ed448ext "github.com/jwx-go/ed448/v4"
	"github.com/jwx-go/es256k/v4"
	jwxmldsa "github.com/jwx-go/mldsa/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
	"gopkg.in/yaml.v3"

	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/go-oidfed/lib/unixtime"
)

// =============================================================================
// Test Helpers
// =============================================================================

// testKey generates a test key for the given algorithm
func testKey(t *testing.T, alg jwa.SignatureAlgorithm) crypto.Signer {
	t.Helper()
	var rsaKeyLen int
	switch alg {
	case jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512():
		rsaKeyLen = 2048
	}
	sk, err := generatePrivateKey(alg, rsaKeyLen)
	require.NoError(t, err)
	return sk
}

// =============================================================================
// Key Generation Tests (jwk.go)
// =============================================================================

func TestGeneratePrivateKey(t *testing.T) {
	t.Run(
		"RSA algorithms", func(t *testing.T) {
			rsaAlgs := []jwa.SignatureAlgorithm{
				jwa.RS256(),
				jwa.RS384(),
				jwa.RS512(),
				jwa.PS256(),
				jwa.PS384(),
				jwa.PS512(),
			}
			for _, alg := range rsaAlgs {
				t.Run(
					alg.String(), func(t *testing.T) {
						sk, err := generatePrivateKey(alg, 2048)
						require.NoError(t, err)
						assert.NotNil(t, sk)
						_, ok := sk.(*rsa.PrivateKey)
						assert.True(t, ok, "expected RSA key")
					},
				)
			}
		},
	)

	t.Run(
		"RSA without key length", func(t *testing.T) {
			sk, err := generatePrivateKey(jwa.RS256(), 0)
			assert.Error(t, err)
			assert.Nil(t, sk)
			assert.Contains(t, err.Error(), "no valid RSA key len")
		},
	)

	t.Run(
		"RSA with negative key length", func(t *testing.T) {
			sk, err := generatePrivateKey(jwa.RS256(), -1)
			assert.Error(t, err)
			assert.Nil(t, sk)
		},
	)

	t.Run(
		"EC algorithms", func(t *testing.T) {
			ecAlgs := []jwa.SignatureAlgorithm{
				jwa.ES256(),
				jwa.ES384(),
				jwa.ES512(),
			}
			for _, alg := range ecAlgs {
				t.Run(
					alg.String(), func(t *testing.T) {
						sk, err := generatePrivateKey(alg, 0)
						require.NoError(t, err)
						assert.NotNil(t, sk)
						_, ok := sk.(*ecdsa.PrivateKey)
						assert.True(t, ok, "expected ECDSA key")
					},
				)
			}
		},
	)

	t.Run(
		"EdDSA", func(t *testing.T) {
			sk, err := generatePrivateKey(jwa.EdDSA(), 0)
			require.NoError(t, err)
			assert.NotNil(t, sk)
			_, ok := sk.(ed25519.PrivateKey)
			assert.True(t, ok, "expected Ed25519 key")
		},
	)

	t.Run(
		"ES256K", func(t *testing.T) {
			sk, err := generatePrivateKey(es256k.ES256K(), 0)
			require.NoError(t, err)
			assert.NotNil(t, sk)
			ecKey, ok := sk.(*ecdsa.PrivateKey)
			assert.True(t, ok, "expected ECDSA key")
			assert.Equal(t, "secp256k1", ecKey.Curve.Params().Name)
		},
	)

	t.Run(
		"Ed448", func(t *testing.T) {
			sk, err := generatePrivateKey(ed448ext.EdDSAEd448(), 0)
			require.NoError(t, err)
			assert.NotNil(t, sk)
			_, ok := sk.(ed448.PrivateKey)
			assert.True(t, ok, "expected Ed448 key")
		},
	)

	t.Run(
		"ML-DSA-44", func(t *testing.T) {
			sk, err := generatePrivateKey(jwxmldsa.MLDSA44(), 0)
			require.NoError(t, err)
			assert.NotNil(t, sk)
			mlKey, ok := sk.(*mldsa.PrivateKey)
			assert.True(t, ok, "expected *mldsa.PrivateKey")
			assert.Equal(t, "ML-DSA-44", mlKey.PublicKey().Parameters().String())
		},
	)

	t.Run(
		"ML-DSA-65", func(t *testing.T) {
			sk, err := generatePrivateKey(jwxmldsa.MLDSA65(), 0)
			require.NoError(t, err)
			assert.NotNil(t, sk)
			mlKey, ok := sk.(*mldsa.PrivateKey)
			assert.True(t, ok, "expected *mldsa.PrivateKey")
			assert.Equal(t, "ML-DSA-65", mlKey.PublicKey().Parameters().String())
		},
	)

	t.Run(
		"ML-DSA-87", func(t *testing.T) {
			sk, err := generatePrivateKey(jwxmldsa.MLDSA87(), 0)
			require.NoError(t, err)
			assert.NotNil(t, sk)
			mlKey, ok := sk.(*mldsa.PrivateKey)
			assert.True(t, ok, "expected *mldsa.PrivateKey")
			assert.Equal(t, "ML-DSA-87", mlKey.PublicKey().Parameters().String())
		},
	)

	t.Run(
		"unknown algorithm", func(t *testing.T) {
			sk, err := generatePrivateKey(jwa.SignatureAlgorithm{}, 0)
			assert.Error(t, err)
			assert.Nil(t, sk)
			assert.Contains(t, err.Error(), "unknown signing algorithm")
		},
	)
}

func TestExportPrivateKeyAsPem(t *testing.T) {
	t.Run(
		"RSA key", func(t *testing.T) {
			sk := testKey(t, jwa.RS256())
			pemData := exportPrivateKeyAsPem(sk)
			require.NotNil(t, pemData)

			block, _ := pem.Decode(pemData)
			require.NotNil(t, block)
			assert.Equal(t, "RSA PRIVATE KEY", block.Type)
		},
	)

	t.Run(
		"ECDSA key", func(t *testing.T) {
			sk := testKey(t, jwa.ES256())
			pemData := exportPrivateKeyAsPem(sk)
			require.NotNil(t, pemData)

			block, _ := pem.Decode(pemData)
			require.NotNil(t, block)
			assert.Equal(t, "EC PRIVATE KEY", block.Type)
		},
	)

	t.Run(
		"Ed25519 key", func(t *testing.T) {
			sk := testKey(t, jwa.EdDSA())
			pemData := exportPrivateKeyAsPem(sk)
			require.NotNil(t, pemData)

			block, _ := pem.Decode(pemData)
			require.NotNil(t, block)
			assert.Equal(t, "PRIVATE KEY", block.Type)
		},
	)

	t.Run(
		"ES256K key", func(t *testing.T) {
			sk := testKey(t, es256k.ES256K())
			pemData := exportPrivateKeyAsPem(sk)
			require.NotNil(t, pemData)

			block, _ := pem.Decode(pemData)
			require.NotNil(t, block)
			assert.Equal(t, "PRIVATE KEY", block.Type)

			parsed, err := parseSecp256k1PKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, "secp256k1", parsed.Curve.Params().Name)
			assert.Equal(t, sk.(*ecdsa.PrivateKey).D, parsed.D)
		},
	)

	t.Run(
		"Ed448 key", func(t *testing.T) {
			sk := testKey(t, ed448ext.EdDSAEd448())
			pemData := exportPrivateKeyAsPem(sk)
			require.NotNil(t, pemData)

			block, _ := pem.Decode(pemData)
			require.NotNil(t, block)
			assert.Equal(t, "PRIVATE KEY", block.Type)

			parsed, err := parseEd448PKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, sk.(ed448.PrivateKey).Seed(), parsed.Seed())
		},
	)

	t.Run(
		"ML-DSA-44 key", func(t *testing.T) {
			sk := testKey(t, jwxmldsa.MLDSA44())
			pemData := exportPrivateKeyAsPem(sk)
			require.NotNil(t, pemData)

			block, _ := pem.Decode(pemData)
			require.NotNil(t, block)
			assert.Equal(t, "PRIVATE KEY", block.Type)

			parsed, err := parseMLDSAPKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, sk.(*mldsa.PrivateKey).Bytes(), parsed.Bytes())
		},
	)

	t.Run(
		"ML-DSA-65 key", func(t *testing.T) {
			sk := testKey(t, jwxmldsa.MLDSA65())
			pemData := exportPrivateKeyAsPem(sk)
			require.NotNil(t, pemData)

			block, _ := pem.Decode(pemData)
			require.NotNil(t, block)
			assert.Equal(t, "PRIVATE KEY", block.Type)

			parsed, err := parseMLDSAPKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, sk.(*mldsa.PrivateKey).Bytes(), parsed.Bytes())
		},
	)

	t.Run(
		"ML-DSA-87 key", func(t *testing.T) {
			sk := testKey(t, jwxmldsa.MLDSA87())
			pemData := exportPrivateKeyAsPem(sk)
			require.NotNil(t, pemData)

			block, _ := pem.Decode(pemData)
			require.NotNil(t, block)
			assert.Equal(t, "PRIVATE KEY", block.Type)

			parsed, err := parseMLDSAPKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, sk.(*mldsa.PrivateKey).Bytes(), parsed.Bytes())
		},
	)

	t.Run(
		"unsupported key type", func(t *testing.T) {
			pemData := exportPrivateKeyAsPem(mockSigner{})
			assert.Nil(t, pemData)
		},
	)
}

// mockSigner is a minimal crypto.Signer for testing unsupported types
type mockSigner struct{}

func (mockSigner) Public() crypto.PublicKey { return nil }
func (mockSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestExportRSAPrivateKeyAsPem(t *testing.T) {
	sk := testKey(t, jwa.RS256()).(*rsa.PrivateKey)
	pemData := exportRSAPrivateKeyAsPem(sk)
	require.NotNil(t, pemData)

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block)
	assert.Equal(t, "RSA PRIVATE KEY", block.Type)
}

func TestExportECPrivateKeyAsPem(t *testing.T) {
	sk := testKey(t, jwa.ES256()).(*ecdsa.PrivateKey)
	pemData := exportECPrivateKeyAsPem(sk)
	require.NotNil(t, pemData)

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block)
	assert.Equal(t, "EC PRIVATE KEY", block.Type)
}

func TestExportEDDSAPrivateKeyAsPem(t *testing.T) {
	sk := testKey(t, jwa.EdDSA()).(ed25519.PrivateKey)
	pemData := exportEDDSAPrivateKeyAsPem(sk)
	require.NotNil(t, pemData)

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)
}

func TestSignerToPublicJWK(t *testing.T) {
	algs := []jwa.SignatureAlgorithm{
		jwa.RS256(),
		jwa.ES256(),
		jwa.EdDSA(),
	}

	for _, alg := range algs {
		t.Run(
			alg.String(), func(t *testing.T) {
				sk := testKey(t, alg)
				pk, kid, err := SignerToPublicJWK(sk, alg)

				require.NoError(t, err)
				assert.NotNil(t, pk)
				assert.NotEmpty(t, kid)

				// Verify kid is set
				keyID, ok := pk.KeyID()
				assert.True(t, ok)
				assert.Equal(t, kid, keyID)

				// Verify algorithm is set
				algVal, ok := pk.Algorithm()
				assert.True(t, ok)
				assert.Equal(t, alg, algVal)

				// Verify key use is set
				useVal, ok := pk.KeyUsage()
				assert.True(t, ok)
				assert.Equal(t, string(jwk.ForSignature), useVal)
			},
		)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	testCases := []struct {
		alg       jwa.SignatureAlgorithm
		rsaKeyLen int
	}{
		{
			jwa.RS256(),
			2048,
		},
		{
			jwa.ES256(),
			0,
		},
		{
			jwa.ES384(),
			0,
		},
		{
			jwa.ES512(),
			0,
		},
		{
			es256k.ES256K(),
			0,
		},
		{
			jwa.EdDSA(),
			0,
		},
		{
			ed448ext.EdDSAEd448(),
			0,
		},
		{
			jwxmldsa.MLDSA44(),
			0,
		},
		{
			jwxmldsa.MLDSA65(),
			0,
		},
		{
			jwxmldsa.MLDSA87(),
			0,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.alg.String(), func(t *testing.T) {
				sk, pk, kid, err := GenerateKeyPair(tc.alg, tc.rsaKeyLen)

				require.NoError(t, err)
				assert.NotNil(t, sk)
				assert.NotNil(t, pk)
				assert.NotEmpty(t, kid)

				// Verify kid matches
				keyID, ok := pk.KeyID()
				assert.True(t, ok)
				assert.Equal(t, kid, keyID)
			},
		)
	}

	t.Run(
		"invalid algorithm", func(t *testing.T) {
			sk, pk, kid, err := GenerateKeyPair(jwa.SignatureAlgorithm{}, 0)
			assert.Error(t, err)
			assert.Nil(t, sk)
			assert.Nil(t, pk)
			assert.Empty(t, kid)
		},
	)
}

// =============================================================================
// JWKS Tests (jwks.go)
// =============================================================================

func TestNewJWKS(t *testing.T) {
	jwks := NewJWKS()
	assert.NotNil(t, jwks.Set)
	assert.Equal(t, 0, jwks.Len())
}

func TestJWKS_MarshalJSON(t *testing.T) {
	t.Run(
		"empty JWKS", func(t *testing.T) {
			jwks := NewJWKS()
			data, err := json.Marshal(jwks)
			require.NoError(t, err)
			assert.Contains(t, string(data), "keys")
		},
	)

	t.Run(
		"JWKS with key", func(t *testing.T) {
			sk := testKey(t, jwa.ES256())
			jwks, err := KeyToJWKS(sk.Public(), jwa.ES256())
			require.NoError(t, err)

			data, err := json.Marshal(jwks)
			require.NoError(t, err)
			assert.Contains(t, string(data), "keys")
			assert.Contains(t, string(data), "ES256")
		},
	)
}

func TestJWKS_UnmarshalJSON(t *testing.T) {
	t.Run(
		"valid JSON", func(t *testing.T) {
			sk := testKey(t, jwa.ES256())
			original, err := KeyToJWKS(sk.Public(), jwa.ES256())
			require.NoError(t, err)

			data, err := json.Marshal(original)
			require.NoError(t, err)

			var jwks JWKS
			err = json.Unmarshal(data, &jwks)
			require.NoError(t, err)
			assert.Equal(t, original.Len(), jwks.Len())
		},
	)

	t.Run(
		"null JSON", func(t *testing.T) {
			var jwks JWKS
			err := json.Unmarshal([]byte("null"), &jwks)
			require.NoError(t, err)
			assert.Nil(t, jwks.Set)
		},
	)

	t.Run(
		"empty keys array", func(t *testing.T) {
			var jwks JWKS
			err := json.Unmarshal([]byte(`{"keys":[]}`), &jwks)
			require.NoError(t, err)
			assert.Nil(t, jwks.Set)
		},
	)

	t.Run(
		"invalid JSON", func(t *testing.T) {
			var jwks JWKS
			err := json.Unmarshal([]byte(`{invalid`), &jwks)
			assert.Error(t, err)
		},
	)
}

func TestJWKS_JSONRoundTrip(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	original, err := KeyToJWKS(sk.Public(), jwa.ES256())
	require.NoError(t, err)

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded JWKS
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Len(), decoded.Len())
}

func TestJWKS_MarshalYAML(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	jwks, err := KeyToJWKS(sk.Public(), jwa.ES256())
	require.NoError(t, err)

	data, err := jwks.MarshalYAML()
	require.NoError(t, err)
	assert.NotNil(t, data)
}

func TestJWKS_UnmarshalYAML(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	original, err := KeyToJWKS(sk.Public(), jwa.ES256())
	require.NoError(t, err)

	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	var generic map[string]any
	err = json.Unmarshal(jsonData, &generic)
	require.NoError(t, err)

	yamlData, err := yaml.Marshal(generic)
	require.NoError(t, err)

	var jwks JWKS
	err = yaml.Unmarshal(yamlData, &jwks)
	require.NoError(t, err)
	assert.Equal(t, original.Len(), jwks.Len())
}

func TestJWKS_MarshalMsgpack(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	jwks, err := KeyToJWKS(sk.Public(), jwa.ES256())
	require.NoError(t, err)

	data, err := jwks.MarshalMsgpack()
	require.NoError(t, err)
	assert.NotNil(t, data)
	assert.True(t, len(data) > 0)
}

func TestJWKS_UnmarshalMsgpack(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	original, err := KeyToJWKS(sk.Public(), jwa.ES256())
	require.NoError(t, err)

	data, err := original.MarshalMsgpack()
	require.NoError(t, err)

	var jwks JWKS
	err = jwks.UnmarshalMsgpack(data)
	require.NoError(t, err)
	assert.Equal(t, original.Len(), jwks.Len())
}

func TestJWKS_MsgpackRoundTrip(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	original, err := KeyToJWKS(sk.Public(), jwa.ES256())
	require.NoError(t, err)

	data, err := msgpack.Marshal(original)
	require.NoError(t, err)

	var decoded JWKS
	err = msgpack.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Len(), decoded.Len())
}

func TestJWKS_MinimalExpirationTime(t *testing.T) {
	t.Run(
		"no keys", func(t *testing.T) {
			jwks := NewJWKS()
			exp := jwks.MinimalExpirationTime()
			assert.True(t, exp.IsZero())
		},
	)

	t.Run(
		"keys without exp", func(t *testing.T) {
			sk := testKey(t, jwa.ES256())
			jwks, err := KeyToJWKS(sk.Public(), jwa.ES256())
			require.NoError(t, err)

			exp := jwks.MinimalExpirationTime()
			assert.True(t, exp.IsZero())
		},
	)

	t.Run(
		"keys with exp", func(t *testing.T) {
			jwks := NewJWKS()

			exp1 := time.Now().Add(time.Hour)
			exp2 := time.Now().Add(2 * time.Hour)

			sk1 := testKey(t, jwa.ES256())
			pk1, err := jwk.PublicKeyOf(sk1.Public())
			require.NoError(t, err)
			require.NoError(t, pk1.Set("exp", unixtime.Unixtime{Time: exp1}))
			require.NoError(t, jwks.AddKey(pk1))

			sk2 := testKey(t, jwa.ES256())
			pk2, err := jwk.PublicKeyOf(sk2.Public())
			require.NoError(t, err)
			require.NoError(t, pk2.Set("exp", unixtime.Unixtime{Time: exp2}))
			require.NoError(t, jwks.AddKey(pk2))

			minExp := jwks.MinimalExpirationTime()
			assert.True(t, minExp.Unix() <= exp1.Unix()+1)
		},
	)
}

func TestJWKS_MaximalExpirationTime(t *testing.T) {
	t.Run(
		"no keys", func(t *testing.T) {
			jwks := NewJWKS()
			exp := jwks.MaximalExpirationTime()
			assert.True(t, exp.IsZero())
		},
	)

	t.Run(
		"keys with exp", func(t *testing.T) {
			jwks := NewJWKS()

			exp1 := time.Now().Add(time.Hour)
			exp2 := time.Now().Add(2 * time.Hour)

			sk1 := testKey(t, jwa.ES256())
			pk1, err := jwk.PublicKeyOf(sk1.Public())
			require.NoError(t, err)
			require.NoError(t, pk1.Set("exp", unixtime.Unixtime{Time: exp1}))
			require.NoError(t, jwks.AddKey(pk1))

			sk2 := testKey(t, jwa.ES256())
			pk2, err := jwk.PublicKeyOf(sk2.Public())
			require.NoError(t, err)
			require.NoError(t, pk2.Set("exp", unixtime.Unixtime{Time: exp2}))
			require.NoError(t, jwks.AddKey(pk2))

			maxExp := jwks.MaximalExpirationTime()
			assert.True(t, maxExp.Unix() >= exp2.Unix()-1)
		},
	)
}

func TestKeyToJWKS(t *testing.T) {
	sk := testKey(t, jwa.ES256())

	jwks, err := KeyToJWKS(sk.Public(), jwa.ES256())
	require.NoError(t, err)

	assert.Equal(t, 1, jwks.Len())

	key, ok := jwks.Key(0)
	require.True(t, ok)

	algVal, ok := key.Algorithm()
	assert.True(t, ok)
	assert.Equal(t, jwa.ES256(), algVal)

	useVal, ok := key.KeyUsage()
	assert.True(t, ok)
	assert.Equal(t, string(jwk.ForSignature), useVal)

	kid, ok := key.KeyID()
	assert.True(t, ok)
	assert.NotEmpty(t, kid)
}

// =============================================================================
// MergeJWKS Tests (jwks.go)
// =============================================================================

// testKeyWithKID creates a public JWK with a specific KID for testing
func testKeyWithKID(t *testing.T, kid string) jwk.Key {
	t.Helper()
	sk := testKey(t, jwa.ES256())
	pk, err := jwk.PublicKeyOf(sk.Public())
	require.NoError(t, err)
	require.NoError(t, pk.Set(jwk.KeyIDKey, kid))
	return pk
}

func TestMergeJWKS_NoOverlap(t *testing.T) {
	jwks1 := NewJWKS()
	jwks2 := NewJWKS()

	require.NoError(t, jwks1.AddKey(testKeyWithKID(t, "key-a")))
	require.NoError(t, jwks2.AddKey(testKeyWithKID(t, "key-b")))

	merged := MergeJWKS(jwks1, jwks2)
	assert.Equal(t, 2, merged.Len())

	kids := map[string]bool{}
	for _, k := range merged.All() {
		if kid, ok := k.KeyID(); ok {
			kids[kid] = true
		}
	}
	assert.True(t, kids["key-a"])
	assert.True(t, kids["key-b"])
}

func TestMergeJWKS_KIDOverlap_PrimaryWins(t *testing.T) {
	jwks1 := NewJWKS()
	jwks2 := NewJWKS()

	pk1 := testKeyWithKID(t, "shared-kid")
	pk2 := testKeyWithKID(t, "shared-kid")

	require.NoError(t, jwks1.AddKey(pk1))
	require.NoError(t, jwks2.AddKey(pk2))

	merged := MergeJWKS(jwks1, jwks2)
	assert.Equal(t, 1, merged.Len())

	k, _ := merged.Key(0)
	assert.Equal(t, pk1, k)
}

func TestMergeJWKS_KeysWithoutKID_AllKept(t *testing.T) {
	jwks1 := NewJWKS()
	jwks2 := NewJWKS()

	sk1 := testKey(t, jwa.ES256())
	pk1, err := jwk.PublicKeyOf(sk1.Public())
	require.NoError(t, err)

	sk2 := testKey(t, jwa.ES256())
	pk2, err := jwk.PublicKeyOf(sk2.Public())
	require.NoError(t, err)

	require.NoError(t, jwks1.AddKey(pk1))
	require.NoError(t, jwks2.AddKey(pk2))

	merged := MergeJWKS(jwks1, jwks2)
	assert.Equal(t, 2, merged.Len())
}

func TestMergeJWKS_EmptyPrimary(t *testing.T) {
	jwks1 := NewJWKS()
	jwks2 := NewJWKS()

	require.NoError(t, jwks2.AddKey(testKeyWithKID(t, "key-b")))

	merged := MergeJWKS(jwks1, jwks2)
	assert.Equal(t, 1, merged.Len())
}

func TestMergeJWKS_EmptySecondary(t *testing.T) {
	jwks1 := NewJWKS()
	jwks2 := NewJWKS()

	require.NoError(t, jwks1.AddKey(testKeyWithKID(t, "key-a")))

	merged := MergeJWKS(jwks1, jwks2)
	assert.Equal(t, 1, merged.Len())
}

func TestMergeJWKS_BothEmpty(t *testing.T) {
	merged := MergeJWKS(NewJWKS(), NewJWKS())
	assert.Equal(t, 0, merged.Len())
}

func TestMergeJWKS_NilSets(t *testing.T) {
	merged := MergeJWKS(JWKS{}, JWKS{})
	assert.NotNil(t, merged.Set)
	assert.Equal(t, 0, merged.Len())
}

// =============================================================================
// JWT Signing Tests (jwtsigning.go)
// =============================================================================

func TestNewGeneralJWTSigner(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	vs := NewSingleKeyVersatileSigner(sk, jwa.ES256())

	signer := NewGeneralJWTSigner(vs, []jwa.SignatureAlgorithm{jwa.ES256()})
	assert.NotNil(t, signer)
}

func TestGeneralJWTSigner_JWT(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	vs := NewSingleKeyVersatileSigner(sk, jwa.ES256())
	signer := NewGeneralJWTSigner(vs, []jwa.SignatureAlgorithm{jwa.ES256()})

	payload := map[string]string{"hello": "world"}

	t.Run(
		"sign with default alg", func(t *testing.T) {
			jwt, err := signer.JWT(payload, "test+jwt")
			require.NoError(t, err)
			assert.NotEmpty(t, jwt)

			parts := strings.Split(string(jwt), ".")
			assert.Len(t, parts, 3)
		},
	)

	t.Run(
		"sign with specific alg", func(t *testing.T) {
			jwt, err := signer.JWT(payload, "test+jwt", "ES256")
			require.NoError(t, err)
			assert.NotEmpty(t, jwt)
		},
	)

	t.Run(
		"no compatible key", func(t *testing.T) {
			jwt, err := signer.JWT(payload, "test+jwt", "RS256")
			assert.Error(t, err)
			assert.Nil(t, jwt)
			assert.Contains(t, err.Error(), "no compatible signing key")
		},
	)
}

func TestGeneralJWTSigner_JWTWithHeaders(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	vs := NewSingleKeyVersatileSigner(sk, jwa.ES256())
	signer := NewGeneralJWTSigner(vs, []jwa.SignatureAlgorithm{jwa.ES256()})

	payload := map[string]string{"hello": "world"}

	t.Run(
		"with custom headers", func(t *testing.T) {
			headers := jws.NewHeaders()
			require.NoError(t, headers.Set("custom", "value"))

			jwt, err := signer.JWTWithHeaders(payload, headers, "test+jwt")
			require.NoError(t, err)
			assert.NotEmpty(t, jwt)
		},
	)

	t.Run(
		"with nil headers", func(t *testing.T) {
			jwt, err := signer.JWTWithHeaders(payload, nil, "test+jwt")
			require.NoError(t, err)
			assert.NotEmpty(t, jwt)
		},
	)
}

func TestGeneralJWTSigner_JWKS(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	vs := NewSingleKeyVersatileSigner(sk, jwa.ES256())
	signer := NewGeneralJWTSigner(vs, []jwa.SignatureAlgorithm{jwa.ES256()})

	jwks, err := signer.JWKS()
	require.NoError(t, err)
	assert.NotNil(t, jwks.Set)
}

func TestGeneralJWTSigner_Typed(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	vs := NewSingleKeyVersatileSigner(sk, jwa.ES256())
	signer := NewGeneralJWTSigner(vs, []jwa.SignatureAlgorithm{jwa.ES256()})

	typed := signer.Typed("custom+jwt")
	assert.NotNil(t, typed)
	assert.Equal(t, "custom+jwt", typed.HeaderType)
}

func TestTypedJWTSigner_JWT(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	vs := NewSingleKeyVersatileSigner(sk, jwa.ES256())
	signer := NewGeneralJWTSigner(vs, []jwa.SignatureAlgorithm{jwa.ES256()})
	typed := signer.Typed("custom+jwt")

	payload := map[string]string{"hello": "world"}
	jwt, err := typed.JWT(payload)
	require.NoError(t, err)
	assert.NotEmpty(t, jwt)
}

func TestEntityStatementSigner(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	vs := NewSingleKeyVersatileSigner(sk, jwa.ES256())
	signer := NewEntityStatementSigner(vs)

	payload := map[string]string{"iss": "https://example.com"}

	t.Run(
		"JWT", func(t *testing.T) {
			jwt, err := signer.JWT(payload)
			require.NoError(t, err)
			assert.NotEmpty(t, jwt)
		},
	)

	t.Run(
		"JWTWithHeaders", func(t *testing.T) {
			headers := jws.NewHeaders()
			jwt, err := signer.JWTWithHeaders(payload, headers)
			require.NoError(t, err)
			assert.NotEmpty(t, jwt)
		},
	)

	t.Run(
		"JWKS", func(t *testing.T) {
			jwks, err := signer.JWKS()
			require.NoError(t, err)
			assert.NotNil(t, jwks.Set)
		},
	)
}

func TestTrustMarkSigner(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	vs := NewSingleKeyVersatileSigner(sk, jwa.ES256())
	signer := NewTrustMarkSigner(vs)

	payload := map[string]string{"id": "https://example.com/tm"}

	jwt, err := signer.JWT(payload)
	require.NoError(t, err)
	assert.NotEmpty(t, jwt)
}

func TestTrustMarkDelegationSigner(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	vs := NewSingleKeyVersatileSigner(sk, jwa.ES256())
	signer := NewTrustMarkDelegationSigner(vs)

	payload := map[string]string{"id": "https://example.com/tm"}

	jwt, err := signer.JWT(payload)
	require.NoError(t, err)
	assert.NotEmpty(t, jwt)
}

func TestResolveResponseSigner(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	vs := NewSingleKeyVersatileSigner(sk, jwa.ES256())
	signer := NewResolveResponseSigner(vs)

	payload := map[string]string{"iss": "https://example.com"}

	jwt, err := signer.JWT(payload)
	require.NoError(t, err)
	assert.NotEmpty(t, jwt)
}

func TestSignWithType(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	payload := []byte(`{"hello":"world"}`)

	t.Run(
		"with nil headers", func(t *testing.T) {
			jwt, err := SignWithType(payload, nil, oidfedconst.JWTTypeEntityStatement, jwa.ES256(), sk)
			require.NoError(t, err)
			assert.NotEmpty(t, jwt)
		},
	)

	t.Run(
		"with existing headers", func(t *testing.T) {
			headers := jws.NewHeaders()
			require.NoError(t, headers.Set("custom", "value"))

			jwt, err := SignWithType(payload, headers, oidfedconst.JWTTypeEntityStatement, jwa.ES256(), sk)
			require.NoError(t, err)
			assert.NotEmpty(t, jwt)
		},
	)
}

func TestSignPayload(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	payload := []byte(`{"hello":"world"}`)

	t.Run(
		"with nil headers", func(t *testing.T) {
			jwt, err := SignPayload(payload, jwa.ES256(), sk, nil)
			require.NoError(t, err)
			assert.NotEmpty(t, jwt)

			parts := strings.Split(string(jwt), ".")
			assert.Len(t, parts, 3)
		},
	)

	t.Run(
		"with headers", func(t *testing.T) {
			headers := jws.NewHeaders()
			require.NoError(t, headers.Set("custom", "value"))

			jwt, err := SignPayload(payload, jwa.ES256(), sk, headers)
			require.NoError(t, err)
			assert.NotEmpty(t, jwt)
		},
	)
}

// =============================================================================
// SingleKeySigner Tests (singleKey.go)
// =============================================================================

func TestNewSingleKeyVersatileSigner(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	signer := NewSingleKeyVersatileSigner(sk, jwa.ES256())
	assert.NotNil(t, signer)
}

func TestSingleKeySigner_Signer(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	signer := NewSingleKeyVersatileSigner(sk, jwa.ES256())

	t.Run(
		"matching algorithm", func(t *testing.T) {
			s, alg := signer.Signer("ES256")
			assert.NotNil(t, s)
			assert.Equal(t, jwa.ES256(), alg)
		},
	)

	t.Run(
		"matching algorithm among multiple", func(t *testing.T) {
			s, alg := signer.Signer("RS256", "ES256", "EdDSA")
			assert.NotNil(t, s)
			assert.Equal(t, jwa.ES256(), alg)
		},
	)

	t.Run(
		"no matching algorithm", func(t *testing.T) {
			s, alg := signer.Signer("RS256", "RS384")
			assert.Nil(t, s)
			assert.Equal(t, jwa.SignatureAlgorithm{}, alg)
		},
	)

	t.Run(
		"empty algs list", func(t *testing.T) {
			s, alg := signer.Signer()
			assert.Nil(t, s)
			assert.Equal(t, jwa.SignatureAlgorithm{}, alg)
		},
	)
}

func TestSingleKeySigner_DefaultSigner(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	signer := NewSingleKeyVersatileSigner(sk, jwa.ES256())

	s, alg := signer.DefaultSigner()
	assert.NotNil(t, s)
	assert.Equal(t, jwa.ES256(), alg)
	assert.Equal(t, sk, s)
}

func TestSingleKeySigner_JWKS(t *testing.T) {
	sk := testKey(t, jwa.ES256())
	signer := NewSingleKeyVersatileSigner(sk, jwa.ES256())

	jwks, err := signer.JWKS()
	require.NoError(t, err)
	assert.NotNil(t, jwks.Set)
	assert.Equal(t, 1, jwks.Len())
}

// =============================================================================
// Algorithms Tests (algs.go)
// =============================================================================

func TestES256K_SignAndVerify(t *testing.T) {
	sk, pk, _, err := GenerateKeyPair(es256k.ES256K(), 0)
	require.NoError(t, err)
	payload := []byte(`{"hello":"secp256k1"}`)

	signed, err := SignWithType(payload, nil, oidfedconst.JWTTypeEntityStatement, es256k.ES256K(), sk)
	require.NoError(t, err)
	assert.NotEmpty(t, signed)

	verified, err := jws.Verify(signed, jws.WithKey(es256k.ES256K(), pk))
	require.NoError(t, err)
	assert.Equal(t, payload, verified)
}

func TestES256K_PEMRoundTrip(t *testing.T) {
	sk := testKey(t, es256k.ES256K()).(*ecdsa.PrivateKey)

	pemData := exportSecp256k1PrivateKeyAsPem(sk)
	require.NotNil(t, pemData)

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	parsed, err := parseSecp256k1PKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, sk.D, parsed.D)
	assert.Equal(t, sk.X, parsed.X)
	assert.Equal(t, sk.Y, parsed.Y)
}

func TestEd448_SignAndVerify(t *testing.T) {
	sk, pk, _, err := GenerateKeyPair(ed448ext.EdDSAEd448(), 0)
	require.NoError(t, err)
	payload := []byte(`{"hello":"ed448"}`)

	signed, err := SignWithType(payload, nil, oidfedconst.JWTTypeEntityStatement, ed448ext.EdDSAEd448(), sk)
	require.NoError(t, err)
	assert.NotEmpty(t, signed)

	verified, err := jws.Verify(signed, jws.WithKey(ed448ext.EdDSAEd448(), pk))
	require.NoError(t, err)
	assert.Equal(t, payload, verified)
}

func TestEd448_PEMRoundTrip(t *testing.T) {
	sk := testKey(t, ed448ext.EdDSAEd448()).(ed448.PrivateKey)

	pemData := exportEd448PrivateKeyAsPem(sk)
	require.NotNil(t, pemData)

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	parsed, err := parseEd448PKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, sk.Seed(), parsed.Seed())
}

func TestMLDSA44_SignAndVerify(t *testing.T) {
	sk, pk, _, err := GenerateKeyPair(jwxmldsa.MLDSA44(), 0)
	require.NoError(t, err)
	payload := []byte(`{"hello":"mldsa44"}`)

	signed, err := SignWithType(payload, nil, oidfedconst.JWTTypeEntityStatement, jwxmldsa.MLDSA44(), sk)
	require.NoError(t, err)
	assert.NotEmpty(t, signed)

	verified, err := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA44(), pk))
	require.NoError(t, err)
	assert.Equal(t, payload, verified)
}

func TestMLDSA44_PEMRoundTrip(t *testing.T) {
	sk := testKey(t, jwxmldsa.MLDSA44()).(*mldsa.PrivateKey)

	pemData := exportMLDSAPrivateKeyAsPem(sk)
	require.NotNil(t, pemData)

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	parsed, err := parseMLDSAPKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, sk.Bytes(), parsed.Bytes())
	assert.True(t, sk.PublicKey().Equal(parsed.PublicKey()))
}

func TestMLDSA65_SignAndVerify(t *testing.T) {
	sk, pk, _, err := GenerateKeyPair(jwxmldsa.MLDSA65(), 0)
	require.NoError(t, err)
	payload := []byte(`{"hello":"mldsa65"}`)

	signed, err := SignWithType(payload, nil, oidfedconst.JWTTypeEntityStatement, jwxmldsa.MLDSA65(), sk)
	require.NoError(t, err)
	assert.NotEmpty(t, signed)

	verified, err := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA65(), pk))
	require.NoError(t, err)
	assert.Equal(t, payload, verified)
}

func TestMLDSA65_PEMRoundTrip(t *testing.T) {
	sk := testKey(t, jwxmldsa.MLDSA65()).(*mldsa.PrivateKey)

	pemData := exportMLDSAPrivateKeyAsPem(sk)
	require.NotNil(t, pemData)

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	parsed, err := parseMLDSAPKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, sk.Bytes(), parsed.Bytes())
	assert.True(t, sk.PublicKey().Equal(parsed.PublicKey()))
}

func TestMLDSA87_SignAndVerify(t *testing.T) {
	sk, pk, _, err := GenerateKeyPair(jwxmldsa.MLDSA87(), 0)
	require.NoError(t, err)
	payload := []byte(`{"hello":"mldsa87"}`)

	signed, err := SignWithType(payload, nil, oidfedconst.JWTTypeEntityStatement, jwxmldsa.MLDSA87(), sk)
	require.NoError(t, err)
	assert.NotEmpty(t, signed)

	verified, err := jws.Verify(signed, jws.WithKey(jwxmldsa.MLDSA87(), pk))
	require.NoError(t, err)
	assert.Equal(t, payload, verified)
}

func TestMLDSA87_PEMRoundTrip(t *testing.T) {
	sk := testKey(t, jwxmldsa.MLDSA87()).(*mldsa.PrivateKey)

	pemData := exportMLDSAPrivateKeyAsPem(sk)
	require.NotNil(t, pemData)

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	parsed, err := parseMLDSAPKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, sk.Bytes(), parsed.Bytes())
	assert.True(t, sk.PublicKey().Equal(parsed.PublicKey()))
}

func TestSupportedAlgs(t *testing.T) {
	algs := SupportedAlgs()

	assert.NotEmpty(t, algs)
	assert.Len(t, algs, 16)

	expectedAlgs := []jwa.SignatureAlgorithm{
		jwa.ES256(),
		jwa.ES384(),
		jwa.ES512(),
		es256k.ES256K(),
		jwa.EdDSA(),
		jwa.EdDSAEd25519(),
		ed448ext.EdDSAEd448(),
		jwa.RS256(),
		jwa.RS384(),
		jwa.RS512(),
		jwa.PS256(),
		jwa.PS384(),
		jwa.PS512(),
		jwxmldsa.MLDSA44(),
		jwxmldsa.MLDSA65(),
		jwxmldsa.MLDSA87(),
	}

	for _, expected := range expectedAlgs {
		found := false
		for _, alg := range algs {
			if alg.String() == expected.String() {
				found = true
				break
			}
		}
		assert.True(t, found, "expected algorithm %s not found", expected.String())
	}
}

func TestSupportedAlgsStrings(t *testing.T) {
	algs := SupportedAlgs()
	strs := SupportedAlgsStrings()

	assert.Len(t, strs, len(algs))

	for i, str := range strs {
		assert.Equal(t, algs[i].String(), str)
	}
}
