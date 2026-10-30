package oidfed

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/cache"
	"github.com/go-oidfed/lib/unixtime"
)

// countingResolver counts how many times it resolved and returns a fixed
// result with a configurable lifetime.
type countingResolver struct {
	calls      int
	validUntil unixtime.Unixtime
}

func (r *countingResolver) ResolveResponsePayload(_ apimodel.ResolveRequest) (ResolveResponsePayload, error) {
	r.calls++
	return ResolveResponsePayload{
		Metadata:   &Metadata{OpenIDProvider: &OpenIDProviderMetadata{Issuer: "https://cached-op.example.com"}},
		TrustChain: make(JWSMessages, 3),
		ValidUntil: r.validUntil,
	}, nil
}

func (r *countingResolver) Resolve(req apimodel.ResolveRequest) (*Metadata, error) {
	res, err := r.ResolveResponsePayload(req)
	if err != nil {
		return nil, err
	}
	return res.Metadata, nil
}

func (r *countingResolver) ResolvePossible(_ apimodel.ResolveRequest) (bool, bool) {
	return false, false
}

func TestResolveOPMetadata_CachesWithHalfLifetime(t *testing.T) {
	old := DefaultMetadataResolver
	defaultCleanup := func() {
		DefaultMetadataResolver = old
		_ = cache.Clear(cache.KeyOPMetadata)
	}
	t.Cleanup(defaultCleanup)
	_ = cache.Clear(cache.KeyOPMetadata)

	resolver := &countingResolver{validUntil: unixtime.Unixtime{Time: time.Now().Add(time.Hour)}}
	DefaultMetadataResolver = resolver
	leaf := newTestFederationLeaf(t)

	opm1, err := leaf.ResolveOPMetadata("https://cached-op.example.com")
	require.NoError(t, err)
	require.NotNil(t, opm1)
	assert.Equal(t, 1, resolver.calls)

	// The second call must be served from the cache, not re-resolved.
	opm2, err := leaf.ResolveOPMetadata("https://cached-op.example.com")
	require.NoError(t, err)
	require.NotNil(t, opm2)
	assert.Equal(t, 1, resolver.calls)
	assert.Equal(t, opm1.Issuer, opm2.Issuer)

	// The cache entry must actually be present with the half-lifetime TTL.
	var cached OpenIDProviderMetadata
	set, err := cache.Get(cache.Key(cache.KeyOPMetadata, "https://cached-op.example.com"), &cached)
	require.NoError(t, err)
	assert.True(t, set)
}

func TestResolveOPMetadata_DoesNotCacheWithoutLifetime(t *testing.T) {
	old := DefaultMetadataResolver
	t.Cleanup(func() {
		DefaultMetadataResolver = old
		_ = cache.Clear(cache.KeyOPMetadata)
	})
	_ = cache.Clear(cache.KeyOPMetadata)

	// Zero ValidUntil: nothing to derive the lifetime from, so nothing may
	// be cached and every call must hit the resolver.
	resolver := &countingResolver{}
	DefaultMetadataResolver = resolver
	leaf := newTestFederationLeaf(t)

	_, err := leaf.ResolveOPMetadata("https://nocache-op.example.com")
	require.NoError(t, err)
	_, err = leaf.ResolveOPMetadata("https://nocache-op.example.com")
	require.NoError(t, err)
	assert.Equal(t, 2, resolver.calls)

	var cached OpenIDProviderMetadata
	set, err := cache.Get(cache.Key(cache.KeyOPMetadata, "https://nocache-op.example.com"), &cached)
	require.NoError(t, err)
	assert.False(t, set)
}

func TestResolveOPMetadata_ExpiredLifetimeIsNotCached(t *testing.T) {
	old := DefaultMetadataResolver
	t.Cleanup(func() {
		DefaultMetadataResolver = old
		_ = cache.Clear(cache.KeyOPMetadata)
	})
	_ = cache.Clear(cache.KeyOPMetadata)

	resolver := &countingResolver{validUntil: unixtime.Unixtime{Time: time.Now().Add(-time.Minute)}}
	DefaultMetadataResolver = resolver
	leaf := newTestFederationLeaf(t)

	_, err := leaf.ResolveOPMetadata("https://expired-op.example.com")
	require.NoError(t, err)
	_, err = leaf.ResolveOPMetadata("https://expired-op.example.com")
	require.NoError(t, err)
	assert.Equal(t, 2, resolver.calls)
}
