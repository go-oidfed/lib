package kms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPEMRoundTripRSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemData, err := exportRSAPrivateKeyAsPEM(privKey)
	require.NoError(t, err)
	require.NotNil(t, pemData)

	signer, err := readSignerFromPEM(pemData, jwa.RS256())
	require.NoError(t, err)
	require.NotNil(t, signer)

	rsaPriv, ok := signer.(*rsa.PrivateKey)
	require.True(t, ok, "Expected *rsa.PrivateKey, got %T", signer)

	assert.Equal(t, privKey.D, rsaPriv.D)
	assert.Equal(t, privKey.N, rsaPriv.N)
}

func TestPEMRoundTripECDSA_P256(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pemData, err := exportECPrivateKeyAsPEM(privKey)
	require.NoError(t, err)
	require.NotNil(t, pemData)

	signer, err := readSignerFromPEM(pemData, jwa.ES256())
	require.NoError(t, err)
	require.NotNil(t, signer)

	ecdsaPriv, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok, "Expected *ecdsa.PrivateKey, got %T", signer)

	assert.Equal(t, privKey.D, ecdsaPriv.D)
	assert.Equal(t, privKey.PublicKey.X, ecdsaPriv.PublicKey.X)
	assert.Equal(t, privKey.PublicKey.Y, ecdsaPriv.PublicKey.Y)
}

func TestPEMRoundTripECDSA_P384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pemData, err := exportECPrivateKeyAsPEM(privKey)
	require.NoError(t, err)
	require.NotNil(t, pemData)

	signer, err := readSignerFromPEM(pemData, jwa.ES384())
	require.NoError(t, err)
	require.NotNil(t, signer)

	ecdsaPriv, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok, "Expected *ecdsa.PrivateKey, got %T", signer)

	assert.Equal(t, privKey.D, ecdsaPriv.D)
	assert.Equal(t, privKey.PublicKey.X, ecdsaPriv.PublicKey.X)
	assert.Equal(t, privKey.PublicKey.Y, ecdsaPriv.PublicKey.Y)
}

func TestPEMRoundTripECDSA_P521(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	pemData, err := exportECPrivateKeyAsPEM(privKey)
	require.NoError(t, err)
	require.NotNil(t, pemData)

	signer, err := readSignerFromPEM(pemData, jwa.ES512())
	require.NoError(t, err)
	require.NotNil(t, signer)

	ecdsaPriv, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok, "Expected *ecdsa.PrivateKey, got %T", signer)

	assert.Equal(t, privKey.D, ecdsaPriv.D)
	assert.Equal(t, privKey.PublicKey.X, ecdsaPriv.PublicKey.X)
	assert.Equal(t, privKey.PublicKey.Y, ecdsaPriv.PublicKey.Y)
}

func TestPEMRoundTripEdDSA(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemData, err := exportEDDSAPrivateKeyAsPEM(privKey)
	require.NoError(t, err)
	require.NotNil(t, pemData)

	signer, err := readSignerFromPEM(pemData, jwa.EdDSA())
	require.NoError(t, err)
	require.NotNil(t, signer)

	edPriv, ok := signer.(ed25519.PrivateKey)
	require.True(t, ok, "Expected ed25519.PrivateKey, got %T", signer)

	assert.Equal(t, privKey, edPriv)
	assert.Equal(t, pubKey, edPriv.Public().(ed25519.PublicKey))
}

func TestPEMReadInvalid(t *testing.T) {
	invalidPEM := []byte("-----BEGIN INVALID-----\nnot valid base64\n-----END INVALID-----")

	signer, err := readSignerFromPEM(invalidPEM, jwa.RS256())
	assert.Error(t, err)
	assert.Nil(t, signer)
}

func TestPEMReadWrongAlg(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemData, err := exportRSAPrivateKeyAsPEM(privKey)
	require.NoError(t, err)

	signer, err := readSignerFromPEM(pemData, jwa.EdDSA())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
	assert.Nil(t, signer)
}

func TestWriteSignerToPEM_UnsupportedType(t *testing.T) {
	unsupported := &mockSigner{}
	pemData, err := writeSignerToPEM(unsupported)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
	assert.Nil(t, pemData)
}

type mockSigner struct{}

func (m *mockSigner) Public() crypto.PublicKey { return nil }
func (m *mockSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}
