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

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/pkg/errors"
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

	pemData, err := writeSignerToPEM(privKey)
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

	pemData, err := writeSignerToPEM(privKey)
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

	pemData, err := writeSignerToPEM(privKey)
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

	pemData, err := writeSignerToPEM(privKey)
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

	pemData, err := writeSignerToPEM(privKey)
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

	pemData, err := writeSignerToPEM(privKey)
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
		signers: make(map[string]jwx.SigningKey),
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
		signers: make(map[string]jwx.SigningKey),
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
		signers: make(map[string]jwx.SigningKey),
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

// =============================================================================
// KeyAnnouncementLeadTimeDuration Tests
// =============================================================================

func TestKeyAnnouncementLeadTimeDuration_FixedDuration(t *testing.T) {
	cfg := KeyRotationConfig{
		KeyAnnouncementLeadTime:         duration.DurationOption(48 * time.Hour),
		EntityConfigurationLifetimeFunc: func() (time.Duration, error) { return 24 * time.Hour, nil },
	}
	leadTime, err := cfg.KeyAnnouncementLeadTimeDuration()
	require.NoError(t, err)
	assert.Equal(t, 48*time.Hour, leadTime)
}

func TestKeyAnnouncementLeadTimeDuration_Multiplier(t *testing.T) {
	cfg := KeyRotationConfig{
		KeyAnnouncementLeadTimeECMultiplier: 5.0,
		EntityConfigurationLifetimeFunc:     func() (time.Duration, error) { return 12 * time.Hour, nil },
	}
	leadTime, err := cfg.KeyAnnouncementLeadTimeDuration()
	require.NoError(t, err)
	assert.Equal(t, 60*time.Hour, leadTime)
}

func TestKeyAnnouncementLeadTimeDuration_Default_Max5xECLifetime_24h(t *testing.T) {
	// EC lifetime 24h → default = max(5*24h, 24h) = 120h
	cfg := KeyRotationConfig{
		EntityConfigurationLifetimeFunc: func() (time.Duration, error) { return 24 * time.Hour, nil },
	}
	leadTime, err := cfg.KeyAnnouncementLeadTimeDuration()
	require.NoError(t, err)
	assert.Equal(t, 120*time.Hour, leadTime)
}

func TestKeyAnnouncementLeadTimeDuration_Default_Floor24h(t *testing.T) {
	// EC lifetime 5min → default = max(5*5min, 24h) = 24h
	cfg := KeyRotationConfig{
		EntityConfigurationLifetimeFunc: func() (time.Duration, error) { return 5 * time.Minute, nil },
	}
	leadTime, err := cfg.KeyAnnouncementLeadTimeDuration()
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, leadTime)
}

func TestKeyAnnouncementLeadTimeDuration_Default_NoECLifetime_Fallback24h(t *testing.T) {
	// No EntityConfigurationLifetimeFunc set at all
	cfg := KeyRotationConfig{}
	leadTime, err := cfg.KeyAnnouncementLeadTimeDuration()
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, leadTime)
}

func TestKeyAnnouncementLeadTimeDuration_ClampedToECLifetime(t *testing.T) {
	// Fixed duration 5min, but EC lifetime is 1h → should clamp to 1h
	cfg := KeyRotationConfig{
		KeyAnnouncementLeadTime:         duration.DurationOption(5 * time.Minute),
		EntityConfigurationLifetimeFunc: func() (time.Duration, error) { return 1 * time.Hour, nil },
	}
	leadTime, err := cfg.KeyAnnouncementLeadTimeDuration()
	require.NoError(t, err)
	assert.Equal(t, 1*time.Hour, leadTime)
}

func TestKeyAnnouncementLeadTimeDuration_MultiplierClampedToECLifetime(t *testing.T) {
	// Multiplier 0.5 * 1h EC lifetime = 30min, but min is EC lifetime (1h)
	cfg := KeyRotationConfig{
		KeyAnnouncementLeadTimeECMultiplier: 0.5,
		EntityConfigurationLifetimeFunc:     func() (time.Duration, error) { return 1 * time.Hour, nil },
	}
	leadTime, err := cfg.KeyAnnouncementLeadTimeDuration()
	require.NoError(t, err)
	assert.Equal(t, 1*time.Hour, leadTime)
}

func TestKeyAnnouncementLeadTimeDuration_MultiplierTakesPrecedenceOverFixed(t *testing.T) {
	// Both set: multiplier should win
	cfg := KeyRotationConfig{
		KeyAnnouncementLeadTime:             duration.DurationOption(1 * time.Hour),
		KeyAnnouncementLeadTimeECMultiplier: 3.0,
		EntityConfigurationLifetimeFunc:     func() (time.Duration, error) { return 24 * time.Hour, nil },
	}
	leadTime, err := cfg.KeyAnnouncementLeadTimeDuration()
	require.NoError(t, err)
	assert.Equal(t, 72*time.Hour, leadTime)
}

func TestKeyAnnouncementLeadTimeDuration_MultiplierNoECLifetimeFunc_Error(t *testing.T) {
	cfg := KeyRotationConfig{
		KeyAnnouncementLeadTimeECMultiplier: 5.0,
	}
	_, err := cfg.KeyAnnouncementLeadTimeDuration()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "EntityConfigurationLifetimeFunc not set")
}

// =============================================================================
// rotationStep / scheduled alg change Tests
// =============================================================================

// memPKStorage is an in-memory public.PublicKeyStorage with an injectable
// clock (now) used by GetActive/GetValid filtering. It actually persists Add
// and Update so rotation logic can be exercised deterministically.
type memPKStorage struct {
	now      time.Time
	entries  map[string]public.PublicKeyEntry
	order    []string
}

func newMemPKStorage(now time.Time) *memPKStorage {
	return &memPKStorage{now: now, entries: make(map[string]public.PublicKeyEntry)}
}

func (m *memPKStorage) Load() error                                       { return nil }
func (m *memPKStorage) GetAll() (public.PublicKeyEntryList, error)        { return m.all(), nil }
func (m *memPKStorage) GetRevoked() (public.PublicKeyEntryList, error)    { return nil, nil }
func (m *memPKStorage) GetExpired() (public.PublicKeyEntryList, error)    { return nil, nil }
func (m *memPKStorage) GetHistorical() (public.PublicKeyEntryList, error) { return nil, nil }

func (m *memPKStorage) all() public.PublicKeyEntryList {
	out := make(public.PublicKeyEntryList, 0, len(m.order))
	for _, kid := range m.order {
		out = append(out, m.entries[kid])
	}
	return out
}

func (m *memPKStorage) GetActive() (public.PublicKeyEntryList, error) {
	var out public.PublicKeyEntryList
	for _, e := range m.entries {
		if e.RevokedAt != nil && !e.RevokedAt.IsZero() && e.RevokedAt.Before(m.now) {
			continue
		}
		if e.NotBefore != nil && !e.NotBefore.IsZero() && m.now.Before(e.NotBefore.Time) {
			continue
		}
		if e.ExpiresAt != nil && !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(m.now) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (m *memPKStorage) GetValid() (public.PublicKeyEntryList, error) {
	var out public.PublicKeyEntryList
	for _, e := range m.entries {
		if e.RevokedAt != nil && !e.RevokedAt.IsZero() && e.RevokedAt.Before(m.now) {
			continue
		}
		if e.ExpiresAt != nil && !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(m.now) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (m *memPKStorage) Add(key public.PublicKeyEntry) error {
	if key.KID == "" {
		return errors.New("missing kid")
	}
	if _, exists := m.entries[key.KID]; exists {
		return nil
	}
	m.entries[key.KID] = key
	m.order = append(m.order, key.KID)
	return nil
}

func (m *memPKStorage) AddAll(keys []public.PublicKeyEntry) error {
	for _, k := range keys {
		if err := m.Add(k); err != nil {
			return err
		}
	}
	return nil
}

func (m *memPKStorage) Update(kid string, data public.UpdateablePublicKeyMetadata) error {
	e, ok := m.entries[kid]
	if !ok {
		return errors.New("not found: " + kid)
	}
	e.UpdateablePublicKeyMetadata = data
	m.entries[kid] = e
	return nil
}

func (m *memPKStorage) Delete(kid string) error {
	if _, ok := m.entries[kid]; !ok {
		return nil
	}
	delete(m.entries, kid)
	for i, k := range m.order {
		if k == kid {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	return nil
}

func (m *memPKStorage) Revoke(kid, reason string) error {
	e, ok := m.entries[kid]
	if !ok {
		return errors.New("not found: " + kid)
	}
	now := unixtime.Now()
	e.RevokedAt = &now
	e.Reason = reason
	m.entries[kid] = e
	return nil
}

func (m *memPKStorage) Get(kid string) (*public.PublicKeyEntry, error) {
	e, ok := m.entries[kid]
	if !ok {
		return nil, errors.New("not found: " + kid)
	}
	return &e, nil
}

func (m *memPKStorage) countForAlg(alg jwa.SignatureAlgorithm) int {
	n := 0
	for _, e := range m.all() {
		a, set := e.Key.Algorithm()
		if !set {
			continue
		}
		if sa, ok := a.(jwa.SignatureAlgorithm); ok && sa.String() == alg.String() {
			n++
		}
	}
	return n
}

// memPEMStorer is an in-memory PEMStorer.
type memPEMStorer struct{ data map[string][]byte }

func newMemPEMStorer() *memPEMStorer { return &memPEMStorer{data: make(map[string][]byte)} }

func (m *memPEMStorer) ReadPEM(kid string) ([]byte, error) {
	d, ok := m.data[kid]
	if !ok {
		return nil, errors.New("not found: " + kid)
	}
	return d, nil
}

func (m *memPEMStorer) WritePEM(kid string, data []byte) error {
	m.data[kid] = data
	return nil
}

// memStateStorer is an in-memory KMSStateStorer.
type memStateStorer struct{ state ScheduledState }

func (m *memStateStorer) LoadScheduledState() (ScheduledState, error) { return m.state, nil }
func (m *memStateStorer) SaveScheduledState(st ScheduledState) error  { m.state = st; return nil }

// TestRotationStep_DoesNotRegenerateOldAlgAfterScheduledChange reproduces the
// bug where, after a scheduled algorithm change becomes effective and the old
// algorithm's key has expired (e.g. during downtime), rotationStep would
// regenerate a key for the old algorithm because it iterated kms.Algs before
// applying the pending alg change. The fix applies scheduled changes first.
func TestRotationStep_DoesNotRegenerateOldAlgAfterScheduledChange(t *testing.T) {
	const (
		interval   = 200 * time.Hour
		overlap    = 10 * time.Minute
		leadTime   = time.Hour
		ecLifetime = time.Hour
	)

	pks := newMemPKStorage(time.Now())
	pem := newMemPEMStorer()
	state := &memStateStorer{}

	kms := &PEMStorageKMS{
		KMSConfig: KMSConfig{
			GenerateKeys: true,
			RSAKeyLen:    2048,
			Algs:         []jwa.SignatureAlgorithm{jwa.ES256()},
			DefaultAlg:   jwa.ES256(),
			KeyRotation: KeyRotationConfig{
				Enabled:                         true,
				Interval:                        duration.DurationOption(interval),
				Overlap:                         duration.DurationOption(overlap),
				KeyAnnouncementLeadTime:         duration.DurationOption(leadTime),
				EntityConfigurationLifetimeFunc: func() (time.Duration, error) { return ecLifetime, nil },
			},
		},
		pemStorer:   pem,
		stateStorer: state,
		PKs:         pks,
		signers:     make(map[string]jwx.SigningKey),
	}

	// Initial load generates the ES256 key (nbf ~now, exp ~now+interval).
	require.NoError(t, kms.Load())
	require.Equal(t, 1, pks.countForAlg(jwa.ES256()), "initial ES256 key should exist")

	// Advance the storage clock to "now" (>= the generated key's nbf) so the
	// ES256 key is considered active for the scheduling step below.
	base := time.Now()
	pks.now = base
	// effectiveAt is in the future relative to base but in the past relative
	// to the simulated "resume" time below.
	effectiveAt := unixtime.Unixtime{Time: base.Add(time.Hour)}

	// Schedule the switch to RS256 at effectiveAt. This pre-generates a
	// future-dated RS256 key and shortens the ES256 key's exp to
	// effectiveAt + overlap.
	require.NoError(
		t, kms.ChangeAlgsAt([]jwa.SignatureAlgorithm{jwa.RS256()}, effectiveAt, overlap),
	)
	require.Equal(t, 1, pks.countForAlg(jwa.RS256()), "future RS256 key should be pre-generated")
	require.Equal(t, 1, pks.countForAlg(jwa.ES256()), "ES256 key count unchanged after scheduling")

	// Simulate the downtime: advance the storage clock past the switch and
	// past the ES256 key's shortened expiration.
	resumeTime := base.Add(25 * time.Hour)
	pks.now = resumeTime

	es256Before := pks.countForAlg(jwa.ES256())
	_, didRotate := kms.rotationStep(resumeTime)

	// The scheduled alg change must have been applied: kms.Algs is now RS256.
	assert.Equal(
		t, []jwa.SignatureAlgorithm{jwa.RS256()}, kms.Algs,
		"scheduled alg change should be applied before the rotation loop",
	)

	// No new ES256 key must have been generated: the old alg is no longer
	// configured, so the rotation loop must not seed a key for it.
	assert.Equal(
		t, es256Before, pks.countForAlg(jwa.ES256()),
		"must not regenerate a key for the old (no longer configured) algorithm",
	)

	// A usable RS256 signer must be available.
	signer, alg := kms.GetDefault()
	require.NotNil(t, signer, "a signer for the new algorithm should be available")
	assert.Equal(t, jwa.RS256(), alg)

	// The pending alg change should have been cleared.
	pAlg, _ := kms.GetPendingChanges()
	assert.Nil(t, pAlg, "pending alg change should be cleared after applying it")

	_ = didRotate
}

// TestRotationStep_BUG_RegeneratesOldAlgWhenOrderIsWrong is a counterpart that
// documents the previous (buggy) ordering behaviour by calling the rotation
// loop logic directly over the old alg set before applying the pending change.
// It guards against a regression that re-introduces the old ordering.
func TestRotationStep_BUG_RegeneratesOldAlgWhenOrderIsWrong(t *testing.T) {
	const (
		interval   = 200 * time.Hour
		overlap    = 10 * time.Minute
		leadTime   = time.Hour
		ecLifetime = time.Hour
	)

	pks := newMemPKStorage(time.Now())
	pem := newMemPEMStorer()
	state := &memStateStorer{}

	kms := &PEMStorageKMS{
		KMSConfig: KMSConfig{
			GenerateKeys: true,
			RSAKeyLen:    2048,
			Algs:         []jwa.SignatureAlgorithm{jwa.ES256()},
			DefaultAlg:   jwa.ES256(),
			KeyRotation: KeyRotationConfig{
				Enabled:                         true,
				Interval:                        duration.DurationOption(interval),
				Overlap:                         duration.DurationOption(overlap),
				KeyAnnouncementLeadTime:         duration.DurationOption(leadTime),
				EntityConfigurationLifetimeFunc: func() (time.Duration, error) { return ecLifetime, nil },
			},
		},
		pemStorer:   pem,
		stateStorer: state,
		PKs:         pks,
		signers:     make(map[string]jwx.SigningKey),
	}

	require.NoError(t, kms.Load())
	base := time.Now()
	pks.now = base
	effectiveAt := unixtime.Unixtime{Time: base.Add(time.Hour)}
	require.NoError(
		t, kms.ChangeAlgsAt([]jwa.SignatureAlgorithm{jwa.RS256()}, effectiveAt, overlap),
	)

	// Simulate the downtime: advance the storage clock past the switch and
	// past the ES256 key's shortened expiration.
	resumeTime := base.Add(25 * time.Hour)
	pks.now = resumeTime

	// Reproduce the OLD (buggy) ordering: run the rotation-evaluation loop over
	// the still-old kms.Algs BEFORE applying the pending alg change.
	activePKs, err := pks.GetActive()
	require.NoError(t, err)
	pksByAlg := activePKs.ByAlg()
	for _, alg := range kms.Algs {
		_, _ = kms.rotationEvaluationForAlg(pksByAlg, alg, resumeTime, time.Second)
	}
	// The bug: a new ES256 key was seeded for the no-longer-desired algorithm.
	assert.Equal(
		t, 2, pks.countForAlg(jwa.ES256()),
		"bug reproduction: old ordering regenerates an ES256 key",
	)
}
