package oidfed

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/go-oidfed/lib/unixtime"
)

// --- Test helpers ---

// rsaSigningKey generates an RSA private key for use as a jwx.SigningKey.
func rsaSigningKey(t *testing.T) jwx.SigningKey {
	t.Helper()
	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return sk
}

// signAsEntityStatement signs an EntityStatementPayload as an entity-statement+jwt.
func signAsEntityStatement(t *testing.T, sk jwx.SigningKey, payload EntityStatementPayload) *EntityStatement {
	t.Helper()
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())
	gs := jwx.NewGeneralJWTSigner(signer, []jwa.SignatureAlgorithm{jwa.RS256()})
	jwtBytes, err := gs.JWT(payload, oidfedconst.JWTTypeEntityStatement)
	require.NoError(t, err)
	es, err := ParseEntityStatement(jwtBytes)
	require.NoError(t, err)
	return es
}

// fakeEC builds an EntityStatement signed with sk for the given entityID,
// jwks, and exp.
func fakeEC(t *testing.T, sk jwx.SigningKey, entityID string, keys jwx.JWKS, exp time.Time) *EntityStatement {
	t.Helper()
	return signAsEntityStatement(t, sk, EntityStatementPayload{
		Issuer:    entityID,
		Subject:   entityID,
		IssuedAt:  unixtime.Now(),
		ExpiresAt: unixtime.Unixtime{Time: exp},
		JWKS:      keys,
	})
}

// fakeECNoExp builds an EntityStatement without an exp claim.
func fakeECNoExp(t *testing.T, sk jwx.SigningKey, entityID string, keys jwx.JWKS) *EntityStatement {
	t.Helper()
	return signAsEntityStatement(t, sk, EntityStatementPayload{
		Issuer:   entityID,
		Subject:  entityID,
		IssuedAt: unixtime.Now(),
		JWKS:     keys,
	})
}

// signJWKSet signs a payload as a jwk-set+jwt with the given key and kid.
func signJWKSet(t *testing.T, sk jwx.SigningKey, kid string, payload any) []byte {
	t.Helper()
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())
	gs := jwx.NewGeneralJWTSigner(signer, []jwa.SignatureAlgorithm{jwa.RS256()})
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.KeyIDKey, kid))
	jwtBytes, err := gs.JWTWithHeaders(payload, headers, oidfedconst.JWTTypeJWKS)
	require.NoError(t, err)
	return jwtBytes
}

// publicJWKSFrom returns a JWKS containing the public key of sk with a kid
// assigned.
func publicJWKSFrom(t *testing.T, sk jwx.SigningKey) jwx.JWKS {
	t.Helper()
	pub, err := jwk.PublicKeyOf(sk)
	require.NoError(t, err)
	require.NoError(t, jwk.AssignKeyID(pub))
	set := jwx.NewJWKS()
	require.NoError(t, set.AddKey(pub))
	return set
}

// --- SubordinateJWKSRefresher tests ---

type memSubStore struct {
	subs       map[string]*SubordinateJWKSInfo
	lastUpdate string
	updated    jwx.JWKS
}

func newMemSubStore(subs ...SubordinateJWKSInfo) *memSubStore {
	m := &memSubStore{subs: make(map[string]*SubordinateJWKSInfo, len(subs))}
	for i := range subs {
		s := subs[i]
		m.subs[s.EntityID] = &s
	}
	return m
}

func (m *memSubStore) ListEnabled() ([]SubordinateJWKSInfo, error) {
	var out []SubordinateJWKSInfo
	for _, s := range m.subs {
		if s.EnableJWKSUpdate {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (m *memSubStore) Get(entityID string) (*SubordinateJWKSInfo, error) {
	if s, ok := m.subs[entityID]; ok {
		cp := *s
		return &cp, nil
	}
	return nil, nil
}

func (m *memSubStore) UpdateJWKS(entityID string, jwks jwx.JWKS) error {
	m.lastUpdate = entityID
	m.updated = jwks
	if s, ok := m.subs[entityID]; ok {
		s.JWKS = jwks
	}
	return nil
}

func TestSubordinateJWKSRefresher_AddDisabledNoPoll(t *testing.T) {
	store := newMemSubStore(SubordinateJWKSInfo{
		EntityID: "https://sub-disabled.example",
		JWKS:     publicJWKSFrom(t, rsaSigningKey(t)),
	})
	r, err := NewSubordinateJWKSRefresher(store, func(string) (*EntityStatement, error) {
		t.Fatal("fetch should not be called for disabled subordinate")
		return nil, nil
	})
	require.NoError(t, err)
	require.NoError(t, r.Start())
	defer r.Stop()
	// Adding a disabled subordinate is a no-op (ensures not polled).
	require.NoError(t, r.Add("https://sub-disabled.example"))
}

func TestSubordinateJWKSRefresher_NoExpErrors(t *testing.T) {
	sk := rsaSigningKey(t)
	storedKeys := publicJWKSFrom(t, sk)
	store := newMemSubStore(SubordinateJWKSInfo{
		EntityID:         "https://sub-noexp.example",
		EnableJWKSUpdate: true,
		JWKS:             storedKeys,
	})
	fetch := func(string) (*EntityStatement, error) {
		return fakeECNoExp(t, sk, "https://sub-noexp.example", storedKeys), nil
	}
	r, err := NewSubordinateJWKSRefresher(store, fetch)
	require.NoError(t, err)
	// Start does not abort on initial poll failure; the no-exp error is
	// surfaced via pollAndMaybeUpdate directly.
	require.NoError(t, r.Start())
	defer r.Stop()
	sub := SubordinateJWKSInfo{
		EntityID:         "https://sub-noexp.example",
		EnableJWKSUpdate: true,
		JWKS:             storedKeys,
	}
	_, err = r.pollAndMaybeUpdate(&sub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exp is required")
}

func TestSubordinateJWKSRefresher_UpdatesOnKIDChange(t *testing.T) {
	sk := rsaSigningKey(t)
	storedKeys := publicJWKSFrom(t, sk) // current/old keys (EC signed by sk)
	newKeys := *createTestJWKS(t, "new-kid")
	store := newMemSubStore(SubordinateJWKSInfo{
		EntityID:         "https://sub-change.example",
		EnableJWKSUpdate: true,
		JWKS:             storedKeys,
	})
	fetch := func(string) (*EntityStatement, error) {
		return fakeEC(t, sk, "https://sub-change.example", newKeys, time.Now().Add(time.Hour)), nil
	}
	r, err := NewSubordinateJWKSRefresher(store, fetch)
	require.NoError(t, err)
	require.NoError(t, r.Start())
	defer r.Stop()
	assert.Equal(t, "https://sub-change.example", store.lastUpdate)
	k, _ := store.updated.Key(0)
	kid, _ := k.KeyID()
	assert.Equal(t, "new-kid", kid)
}

func TestSubordinateJWKSRefresher_NoChangeNoUpdate(t *testing.T) {
	sk := rsaSigningKey(t)
	keys := publicJWKSFrom(t, sk)
	store := newMemSubStore(SubordinateJWKSInfo{
		EntityID:         "https://sub-same.example",
		EnableJWKSUpdate: true,
		JWKS:             keys,
	})
	fetch := func(string) (*EntityStatement, error) {
		return fakeEC(t, sk, "https://sub-same.example", keys, time.Now().Add(time.Hour)), nil
	}
	r, err := NewSubordinateJWKSRefresher(store, fetch)
	require.NoError(t, err)
	require.NoError(t, r.Start())
	defer r.Stop()
	assert.Equal(t, "", store.lastUpdate, "storage should not be touched when JWKS unchanged")
}

// registerState adds a poll-state entry for sub without performing an initial
// poll, so tests can call pollAndMaybeUpdate directly.
func registerState(r *SubordinateJWKSRefresher, sub *SubordinateJWKSInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state[sub.EntityID] = &subPollState{
		lastKnownKIDs: ExtractKIDs(sub.JWKS),
		backoff:       subInitialBackoff,
		stopCh:        make(chan struct{}),
	}
}

func TestSubordinateJWKSRefresher_PerSubordinateIntervalWins(t *testing.T) {
	sk := rsaSigningKey(t)
	keys := publicJWKSFrom(t, sk)
	var interval int64 = 42
	store := newMemSubStore(SubordinateJWKSInfo{
		EntityID:         "https://sub-int.example",
		EnableJWKSUpdate: true,
		JWKSPollInterval: &interval,
		JWKS:             keys,
	})
	fetch := func(string) (*EntityStatement, error) {
		return fakeEC(t, sk, "https://sub-int.example", keys, time.Now().Add(time.Hour)), nil
	}
	r, err := NewSubordinateJWKSRefresher(store, fetch)
	require.NoError(t, err)
	sub := SubordinateJWKSInfo{
		EntityID:         "https://sub-int.example",
		EnableJWKSUpdate: true,
		JWKSPollInterval: &interval,
		JWKS:             keys,
	}
	registerState(r, &sub)
	d, err := r.pollAndMaybeUpdate(&sub)
	require.NoError(t, err)
	assert.Equal(t, 42*time.Second, d)
}

func TestSubordinateJWKSRefresher_ECExpIntervalWhenNoConfig(t *testing.T) {
	sk := rsaSigningKey(t)
	keys := publicJWKSFrom(t, sk)
	store := newMemSubStore(SubordinateJWKSInfo{
		EntityID:         "https://sub-exp.example",
		EnableJWKSUpdate: true,
		JWKS:             keys,
	})
	ecExp := time.Now().Add(2 * time.Hour)
	fetch := func(string) (*EntityStatement, error) {
		return fakeEC(t, sk, "https://sub-exp.example", keys, ecExp), nil
	}
	r, err := NewSubordinateJWKSRefresher(store, fetch)
	require.NoError(t, err)
	sub := SubordinateJWKSInfo{
		EntityID:         "https://sub-exp.example",
		EnableJWKSUpdate: true,
		JWKS:             keys,
	}
	registerState(r, &sub)
	d, err := r.pollAndMaybeUpdate(&sub)
	require.NoError(t, err)
	assert.InDelta(t, time.Until(ecExp).Seconds(), d.Seconds(), 2)
}

func TestSubordinateJWKSRefresher_ECExpFlooredToMin(t *testing.T) {
	sk := rsaSigningKey(t)
	keys := publicJWKSFrom(t, sk)
	ecExp := time.Now().Add(10 * time.Second)
	fetch := func(string) (*EntityStatement, error) {
		return fakeEC(t, sk, "https://sub-floor.example", keys, ecExp), nil
	}
	r, err := NewSubordinateJWKSRefresher(newMemSubStore(), fetch)
	require.NoError(t, err)
	sub := SubordinateJWKSInfo{
		EntityID:         "https://sub-floor.example",
		EnableJWKSUpdate: true,
		JWKS:             keys,
	}
	registerState(r, &sub)
	d, err := r.pollAndMaybeUpdate(&sub)
	require.NoError(t, err)
	assert.Equal(t, SubMinPollInterval, d)
}

func TestSubordinateJWKSRefresher_Remove(t *testing.T) {
	sk := rsaSigningKey(t)
	store := newMemSubStore(SubordinateJWKSInfo{
		EntityID:         "https://sub-rm.example",
		EnableJWKSUpdate: true,
		JWKS:             publicJWKSFrom(t, sk),
	})
	r, err := NewSubordinateJWKSRefresher(store, func(string) (*EntityStatement, error) {
		return nil, nil
	})
	require.NoError(t, err)
	require.NoError(t, r.Add("https://sub-rm.example"))
	r.Remove("https://sub-rm.example")
	r.mu.Lock()
	_, exists := r.state["https://sub-rm.example"]
	r.mu.Unlock()
	assert.False(t, exists)
}

func TestSubordinateJWKSRefresher_SigVerifyFailure(t *testing.T) {
	storedKeys := publicJWKSFrom(t, rsaSigningKey(t))
	otherSK := rsaSigningKey(t)
	ecKeys := publicJWKSFrom(t, otherSK)
	store := newMemSubStore(SubordinateJWKSInfo{
		EntityID:         "https://sub-sigfail.example",
		EnableJWKSUpdate: true,
		JWKS:             storedKeys,
	})
	fetch := func(string) (*EntityStatement, error) {
		return fakeEC(t, otherSK, "https://sub-sigfail.example", ecKeys, time.Now().Add(time.Hour)), nil
	}
	r, err := NewSubordinateJWKSRefresher(store, fetch)
	require.NoError(t, err)
	sub := SubordinateJWKSInfo{
		EntityID:         "https://sub-sigfail.example",
		EnableJWKSUpdate: true,
		JWKS:             storedKeys,
	}
	registerState(r, &sub)
	_, err = r.pollAndMaybeUpdate(&sub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
	assert.Equal(t, "", store.lastUpdate, "storage must not be updated on signature failure")
}

// --- ParseSignedJWKS tests ---

func TestParseSignedJWKS_HappyPath(t *testing.T) {
	sk := rsaSigningKey(t)
	pubJWK, err := jwk.PublicKeyOf(sk)
	require.NoError(t, err)
	require.NoError(t, jwk.AssignKeyID(pubJWK))
	kid, _ := pubJWK.KeyID()
	keys := jwx.NewJWKS()
	require.NoError(t, keys.AddKey(pubJWK))

	payload := map[string]any{
		"keys": keys,
		"iss":  "https://sub.example",
		"sub":  "https://sub.example",
		"iat":  time.Now().Unix(),
	}
	jwtBytes := signJWKSet(t, sk, kid, payload)

	parsed, err := ParseSignedJWKS(jwtBytes)
	require.NoError(t, err)
	assert.Equal(t, "https://sub.example", parsed.Issuer)
	assert.Equal(t, "https://sub.example", parsed.Subject)
	assert.Equal(t, 1, parsed.Keys.Len())
	gotKID, ok := parsed.KID()
	require.True(t, ok)
	assert.Equal(t, kid, gotKID)

	verifySet := jwx.NewJWKS()
	require.NoError(t, verifySet.AddKey(pubJWK))
	assert.True(t, parsed.Verify(verifySet))
}

func TestParseSignedJWKS_WrongTyp(t *testing.T) {
	sk := rsaSigningKey(t)
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())
	gs := jwx.NewGeneralJWTSigner(signer, []jwa.SignatureAlgorithm{jwa.RS256()})
	jwtBytes, err := gs.JWT(
		map[string]any{"keys": []any{}, "iss": "x", "sub": "x"}, oidfedconst.JWTTypeEntityStatement,
	)
	require.NoError(t, err)
	_, err = ParseSignedJWKS(jwtBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not have 'jwk-set+jwt' JWT type")
}

func TestParseSignedJWKS_EmptyKIDHeader(t *testing.T) {
	sk := rsaSigningKey(t)
	pubJWK, err := jwk.PublicKeyOf(sk)
	require.NoError(t, err)
	require.NoError(t, jwk.AssignKeyID(pubJWK))
	keys := jwx.NewJWKS()
	require.NoError(t, keys.AddKey(pubJWK))
	payload := map[string]any{"keys": keys, "iss": "x", "sub": "x"}
	payloadBytes, _ := json.Marshal(payload)
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, oidfedconst.JWTTypeJWKS))
	require.NoError(t, headers.Set(jws.KeyIDKey, ""))
	jwtBytes, err := jws.Sign(
		payloadBytes, jws.WithKey(jwa.RS256(), sk, jws.WithProtectedHeaders(headers)),
	)
	require.NoError(t, err)
	_, err = ParseSignedJWKS(jwtBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kid")
}

func TestParseSignedJWKS_DuplicateKID(t *testing.T) {
	sk := rsaSigningKey(t)
	// Two distinct keys, both with the same kid, to trigger duplicate detection.
	pub1, err := jwk.PublicKeyOf(rsaSigningKey(t))
	require.NoError(t, err)
	require.NoError(t, pub1.Set(jwk.KeyIDKey, "dup-kid"))
	pub2, err := jwk.PublicKeyOf(rsaSigningKey(t))
	require.NoError(t, err)
	require.NoError(t, pub2.Set(jwk.KeyIDKey, "dup-kid"))
	keys := jwx.NewJWKS()
	require.NoError(t, keys.AddKey(pub1))
	require.NoError(t, keys.AddKey(pub2))
	payload := map[string]any{
		"keys": keys,
		"iss":  "https://sub.example",
		"sub":  "https://sub.example",
	}
	jwtBytes := signJWKSet(t, sk, "any-kid", payload)
	_, err = ParseSignedJWKS(jwtBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate kid")
}

func TestParseSignedJWKS_MissingIssOrSub(t *testing.T) {
	sk := rsaSigningKey(t)
	pubJWK, err := jwk.PublicKeyOf(sk)
	require.NoError(t, err)
	require.NoError(t, jwk.AssignKeyID(pubJWK))
	keys := jwx.NewJWKS()
	require.NoError(t, keys.AddKey(pubJWK))

	payload := map[string]any{"keys": keys, "sub": "https://sub.example"}
	jwtBytes := signJWKSet(t, sk, "k", payload)
	_, err = ParseSignedJWKS(jwtBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iss")

	payload2 := map[string]any{"keys": keys, "iss": "https://sub.example"}
	jwtBytes2 := signJWKSet(t, sk, "k", payload2)
	_, err = ParseSignedJWKS(jwtBytes2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sub")
}

func TestParseSignedJWKS_EmptyKeys(t *testing.T) {
	sk := rsaSigningKey(t)
	empty := jwx.NewJWKS()
	payload := map[string]any{"keys": empty, "iss": "x", "sub": "x"}
	jwtBytes := signJWKSet(t, sk, "k", payload)
	_, err := ParseSignedJWKS(jwtBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keys")
}
