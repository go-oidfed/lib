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
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zachmann/go-utils/duration"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/public"
	"github.com/go-oidfed/lib/unixtime"
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

func TestSortKeysByPreference(t *testing.T) {
	now := time.Now()
	overlap := 30 * time.Minute

	t.Run(
		"single key", func(t *testing.T) {
			keys := []public.PublicKeyEntry{
				{KID: "key1"},
			}
			indices := sortKeysByPreference(keys, overlap)
			assert.Equal(t, []int{0}, indices)
		},
	)

	t.Run(
		"prefers key with nbf in past and latest expiration", func(t *testing.T) {
			nbfPast := unixtime.Unixtime{Time: now.Add(-1 * time.Hour)}
			exp1 := unixtime.Unixtime{Time: now.Add(2 * time.Hour)}
			exp2 := unixtime.Unixtime{Time: now.Add(4 * time.Hour)}

			keys := []public.PublicKeyEntry{
				{
					KID:                         "key1",
					NotBefore:                   &nbfPast,
					UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{ExpiresAt: &exp1},
				},
				{
					KID:                         "key2",
					NotBefore:                   &nbfPast,
					UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{ExpiresAt: &exp2},
				},
			}
			indices := sortKeysByPreference(keys, overlap)
			assert.Equal(
				t, []int{
					1,
					0,
				}, indices,
			)
		},
	)

	t.Run(
		"handles nil expiration", func(t *testing.T) {
			nbfPast := unixtime.Unixtime{Time: now.Add(-1 * time.Hour)}
			exp := unixtime.Unixtime{Time: now.Add(2 * time.Hour)}

			keys := []public.PublicKeyEntry{
				{
					KID:                         "key1",
					NotBefore:                   &nbfPast,
					UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{ExpiresAt: &exp},
				},
				{
					KID:                         "key2",
					NotBefore:                   &nbfPast,
					UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{ExpiresAt: nil},
				},
			}
			indices := sortKeysByPreference(keys, overlap)
			assert.NotEmpty(t, indices)
		},
	)
}

func TestGetForAlgs_OrphanedPublicKey(t *testing.T) {
	kms := &PEMStorageKMS{
		signers: make(map[string]crypto.Signer),
		KMSConfig: KMSConfig{
			Algs:       []jwa.SignatureAlgorithm{jwa.RS256()},
			DefaultAlg: jwa.RS256(),
			KeyRotation: KeyRotationConfig{
				Overlap: duration.DurationOption(30 * time.Minute),
			},
		},
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, pk1, kid1, err := jwx.GenerateKeyPair(jwa.RS256(), 2048)
	require.NoError(t, err)

	_, pk2, kid2, err := jwx.GenerateKeyPair(jwa.RS256(), 2048)
	require.NoError(t, err)

	nbfPast := unixtime.Unixtime{Time: time.Now().Add(-1 * time.Hour)}
	exp1 := unixtime.Unixtime{Time: time.Now().Add(2 * time.Hour)}
	exp2 := unixtime.Unixtime{Time: time.Now().Add(4 * time.Hour)}

	mockPKs := &mockPublicKeyStorage{
		activeKeys: []public.PublicKeyEntry{
			{
				KID:       kid1,
				Key:       public.JWKKey{Key: pk1},
				NotBefore: &nbfPast,
				UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{
					ExpiresAt: &exp1,
				},
			},
			{
				KID:       kid2,
				Key:       public.JWKKey{Key: pk2},
				NotBefore: &nbfPast,
				UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{
					ExpiresAt: &exp2,
				},
			},
		},
	}
	kms.PKs = mockPKs

	kms.signers[kid1] = privKey

	signer, alg := kms.GetForAlgs("RS256")
	assert.NotNil(t, signer, "Should find signer even though preferred key is orphaned")
	assert.Equal(t, jwa.RS256(), alg)
}

func TestGetForAlgs_AllOrphanedKeysForAlg(t *testing.T) {
	kms := &PEMStorageKMS{
		signers: make(map[string]crypto.Signer),
		KMSConfig: KMSConfig{
			Algs:       []jwa.SignatureAlgorithm{jwa.RS256()},
			DefaultAlg: jwa.RS256(),
			KeyRotation: KeyRotationConfig{
				Overlap: duration.DurationOption(30 * time.Minute),
			},
		},
	}

	_, pk1, kid1, err := jwx.GenerateKeyPair(jwa.RS256(), 2048)
	require.NoError(t, err)

	_, pk2, kid2, err := jwx.GenerateKeyPair(jwa.RS256(), 2048)
	require.NoError(t, err)

	nbfPast := unixtime.Unixtime{Time: time.Now().Add(-1 * time.Hour)}
	exp1 := unixtime.Unixtime{Time: time.Now().Add(2 * time.Hour)}
	exp2 := unixtime.Unixtime{Time: time.Now().Add(4 * time.Hour)}

	mockPKs := &mockPublicKeyStorage{
		activeKeys: []public.PublicKeyEntry{
			{
				KID:       kid1,
				Key:       public.JWKKey{Key: pk1},
				NotBefore: &nbfPast,
				UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{
					ExpiresAt: &exp1,
				},
			},
			{
				KID:       kid2,
				Key:       public.JWKKey{Key: pk2},
				NotBefore: &nbfPast,
				UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{
					ExpiresAt: &exp2,
				},
			},
		},
	}
	kms.PKs = mockPKs

	signer, alg := kms.GetForAlgs("RS256")
	assert.Nil(t, signer, "Should return nil when all keys are orphaned")
	assert.Equal(t, jwa.SignatureAlgorithm{}, alg)
}

func TestGetForAlgs_MultipleAlgsWithMixedOrphans(t *testing.T) {
	kms := &PEMStorageKMS{
		signers: make(map[string]crypto.Signer),
		KMSConfig: KMSConfig{
			Algs: []jwa.SignatureAlgorithm{
				jwa.RS256(),
				jwa.ES256(),
			},
			DefaultAlg: jwa.RS256(),
			KeyRotation: KeyRotationConfig{
				Overlap: duration.DurationOption(30 * time.Minute),
			},
		},
	}

	_, rsaPK, rsaKid, err := jwx.GenerateKeyPair(jwa.RS256(), 2048)
	require.NoError(t, err)

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, ecPK, ecKid, err := jwx.GenerateKeyPair(jwa.ES256(), 0)
	require.NoError(t, err)

	nbfPast := unixtime.Unixtime{Time: time.Now().Add(-1 * time.Hour)}
	exp := unixtime.Unixtime{Time: time.Now().Add(2 * time.Hour)}

	mockPKs := &mockPublicKeyStorage{
		activeKeys: []public.PublicKeyEntry{
			{
				KID:       rsaKid,
				Key:       public.JWKKey{Key: rsaPK},
				NotBefore: &nbfPast,
				UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{
					ExpiresAt: &exp,
				},
			},
			{
				KID:       ecKid,
				Key:       public.JWKKey{Key: ecPK},
				NotBefore: &nbfPast,
				UpdateablePublicKeyMetadata: public.UpdateablePublicKeyMetadata{
					ExpiresAt: &exp,
				},
			},
		},
	}
	kms.PKs = mockPKs

	kms.signers[ecKid] = ecPriv

	signer, alg := kms.GetForAlgs("RS256", "ES256")
	assert.NotNil(t, signer, "Should find ES256 signer even though RS256 is orphaned")
	assert.Equal(t, jwa.ES256(), alg)
}

type mockPublicKeyStorage struct {
	activeKeys []public.PublicKeyEntry
}

func (m *mockPublicKeyStorage) Load() error                                       { return nil }
func (m *mockPublicKeyStorage) GetAll() (public.PublicKeyEntryList, error)        { return m.activeKeys, nil }
func (m *mockPublicKeyStorage) GetRevoked() (public.PublicKeyEntryList, error)    { return nil, nil }
func (m *mockPublicKeyStorage) GetExpired() (public.PublicKeyEntryList, error)    { return nil, nil }
func (m *mockPublicKeyStorage) GetHistorical() (public.PublicKeyEntryList, error) { return nil, nil }
func (m *mockPublicKeyStorage) GetActive() (public.PublicKeyEntryList, error) {
	return m.activeKeys, nil
}
func (m *mockPublicKeyStorage) GetValid() (public.PublicKeyEntryList, error) {
	return m.activeKeys, nil
}
func (m *mockPublicKeyStorage) Add(public.PublicKeyEntry) error      { return nil }
func (m *mockPublicKeyStorage) AddAll([]public.PublicKeyEntry) error { return nil }
func (m *mockPublicKeyStorage) Update(string, public.UpdateablePublicKeyMetadata) error {
	return nil
}
func (m *mockPublicKeyStorage) Delete(string) error         { return nil }
func (m *mockPublicKeyStorage) Revoke(string, string) error { return nil }
func (m *mockPublicKeyStorage) Get(string) (*public.PublicKeyEntry, error) {
	for _, k := range m.activeKeys {
		if k.KID == m.activeKeys[0].KID {
			return &k, nil
		}
	}
	return nil, nil
}
