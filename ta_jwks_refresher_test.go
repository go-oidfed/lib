package oidfed

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-oidfed/lib/jwx"
)

// TestTAJWKSRefresher_AddDisabledNoPoll verifies that Add with
// EnableJWKSUpdate=false registers the TA without attempting a poll.
func TestTAJWKSRefresher_AddDisabledNoPoll(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	tas := TrustAnchors{}
	refresher, err := NewTAJWKSRefresher(&tas, store)
	require.NoError(t, err)

	ta := &TrustAnchor{EntityID: "https://ta-no-poll.example", EnableJWKSUpdate: false}
	ta.SetJWKS(*createTestJWKS(t, "k1"))

	// Not started yet; Add should still register without polling.
	require.NoError(t, refresher.Add(ta))
	assert.Equal(t, 1, len(tas))
	assert.Equal(t, "https://ta-no-poll.example", tas[0].EntityID)
}

// TestTAJWKSRefresher_AddReplace verifies that adding a TA with an existing
// entity_id replaces it rather than duplicating.
func TestTAJWKSRefresher_AddReplace(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	ta1 := &TrustAnchor{EntityID: "https://ta-replace.example", EnableJWKSUpdate: false}
	ta1.SetJWKS(*createTestJWKS(t, "old"))
	tas := TrustAnchors{ta1}

	refresher, err := NewTAJWKSRefresher(&tas, store)
	require.NoError(t, err)

	ta2 := &TrustAnchor{EntityID: "https://ta-replace.example", EnableJWKSUpdate: false}
	ta2.SetJWKS(*createTestJWKS(t, "new"))

	require.NoError(t, refresher.Add(ta2))
	assert.Equal(t, 1, len(tas), "should replace, not duplicate")
	assert.Equal(t, "new", func() string {
		k, _ := tas[0].JWKS().Key(0)
		kid, _ := k.KeyID()
		return kid
	}())
}

// TestTAJWKSRefresher_Remove verifies Remove drops the TA from the slice.
func TestTAJWKSRefresher_Remove(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	ta1 := &TrustAnchor{EntityID: "https://ta-keep.example", EnableJWKSUpdate: false}
	ta1.SetJWKS(*createTestJWKS(t, "keep"))
	ta2 := &TrustAnchor{EntityID: "https://ta-remove.example", EnableJWKSUpdate: false}
	ta2.SetJWKS(*createTestJWKS(t, "remove"))
	tas := TrustAnchors{ta1, ta2}

	refresher, err := NewTAJWKSRefresher(&tas, store)
	require.NoError(t, err)

	refresher.Remove("https://ta-remove.example")
	assert.Equal(t, 1, len(tas))
	assert.Equal(t, "https://ta-keep.example", tas[0].EntityID)

	// Removing a non-existent TA is a no-op.
	refresher.Remove("https://nope.example")
	assert.Equal(t, 1, len(tas))
}

// TestTAJWKSRefresher_UpdateViaAdd verifies Update delegates to Add for a new
// entity when it is not yet registered.
func TestTAJWKSRefresher_UpdateViaAdd(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	tas := TrustAnchors{}
	refresher, err := NewTAJWKSRefresher(&tas, store)
	require.NoError(t, err)

	ta := &TrustAnchor{EntityID: "https://ta-update.example", EnableJWKSUpdate: false}
	ta.SetJWKS(*createTestJWKS(t, "u1"))

	require.NoError(t, refresher.Update(ta))
	assert.Equal(t, 1, len(tas))
}

// TestTAJWKSRefresher_FirstPollSeedValidation verifies that Start() does not
// return the "no JWKS available" error when storage is available to seed; it
// instead attempts the initial poll, which fails for a non-existent entity
// without failing Start: the TA is polled again in the background.
func TestTAJWKSRefresher_FirstPollSeedValidation(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	// TA with no JWKS and EnableJWKSUpdate=true.
	ta := &TrustAnchor{EntityID: "https://ta-seed.example", EnableJWKSUpdate: true}
	tas := TrustAnchors{ta}

	refresher, err := NewTAJWKSRefresher(&tas, store)
	require.NoError(t, err)

	require.NoError(t, refresher.Start(), "a failed initial poll does not fail Start")
	assert.True(t, refresher.IsStarted())
	assert.Nil(t, ta.JWKS().Set, "no JWKS until a poll succeeds")
	refresher.Stop()
}

// TestTAJWKSRefresher_AddUnreachableKeepsJWKS verifies that adding a TA whose
// entity configuration cannot be fetched succeeds and keeps its JWKS.
func TestTAJWKSRefresher_AddUnreachableKeepsJWKS(t *testing.T) {
	store, err := NewFileJWKStorage(t.TempDir())
	require.NoError(t, err)
	tas := TrustAnchors{}
	refresher, err := NewTAJWKSRefresher(&tas, store)
	require.NoError(t, err)
	require.NoError(t, refresher.Start())
	defer refresher.Stop()

	_, pk, _, err := jwx.GenerateKeyPair(jwa.ES256(), 0)
	require.NoError(t, err)
	jwks := jwx.NewJWKS()
	require.NoError(t, jwks.AddKey(pk))
	ta := &TrustAnchor{EntityID: "https://ta-unreachable.example", EnableJWKSUpdate: true}
	ta.SetJWKS(jwks)
	require.NoError(t, refresher.Add(ta))
	assert.Equal(t, jwks.Len(), ta.JWKS().Len())
}

// TestTAJWKSRefresher_FailedInitialPollRetried verifies that a TA whose
// initial poll fails is polled again after the initial backoff.
func TestTAJWKSRefresher_FailedInitialPollRetried(t *testing.T) {
	const entityID = "https://ta-retry.example"
	var polls atomic.Int32
	httpmock.RegisterResponder(
		http.MethodGet, entityID+"/.well-known/openid-federation",
		func(*http.Request) (*http.Response, error) {
			polls.Add(1)
			return httpmock.NewStringResponse(http.StatusServiceUnavailable, ""), nil
		},
	)

	_, pk, _, err := jwx.GenerateKeyPair(jwa.ES256(), 0)
	require.NoError(t, err)
	jwks := jwx.NewJWKS()
	require.NoError(t, jwks.AddKey(pk))
	ta := &TrustAnchor{EntityID: entityID, EnableJWKSUpdate: true}
	ta.SetJWKS(jwks)
	tas := TrustAnchors{ta}
	store, err := NewFileJWKStorage(t.TempDir())
	require.NoError(t, err)
	refresher, err := NewTAJWKSRefresher(&tas, store)
	require.NoError(t, err)

	require.NoError(t, refresher.Start())
	defer refresher.Stop()
	require.GreaterOrEqual(t, polls.Load(), int32(1), "the initial poll reached the TA")
	assert.Eventually(
		t, func() bool { return polls.Load() >= 2 }, 5*time.Second, 50*time.Millisecond,
		"the TA is polled again after the initial backoff",
	)
	assert.Equal(t, jwks.Len(), ta.JWKS().Len(), "the TA keeps its JWKS")
}

// TestTAJWKSRefresher_FirstPollSeedNoStorageErrors verifies that without
// storage, a TA with no JWKS and EnableJWKSUpdate=true produces the explicit
// "no JWKS available" error from Start().
func TestTAJWKSRefresher_FirstPollSeedNoStorageErrors(t *testing.T) {
	ta := &TrustAnchor{EntityID: "https://ta-nostorage.example", EnableJWKSUpdate: true}
	tas := TrustAnchors{ta}

	refresher, err := NewTAJWKSRefresher(&tas, nil)
	require.NoError(t, err)

	startErr := refresher.Start()
	require.Error(t, startErr)
	assert.Contains(t, startErr.Error(), "no JWKS available")
}

// TestTAJWKSRefresher_IsStarted reports the started state.
func TestTAJWKSRefresher_IsStarted(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)
	tas := TrustAnchors{}
	refresher, err := NewTAJWKSRefresher(&tas, store)
	require.NoError(t, err)

	assert.False(t, refresher.IsStarted())
}

// TestDBJWKStorageInterface is a compile-time check that a storage impl with
// UpdateJWKS/GetJWKS/RegisterEntityJWKSFile satisfies JWKStorage.
func TestJWKStorageInterfaceCompile(t *testing.T) {
	var _ JWKStorage = (*FileJWKStorage)(nil)
}

// dummy reference to keep jwx import in case future tests use it.
var _ = jwx.NewJWKS
var _ time.Duration
