package oidfed

import (
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"

	"github.com/go-oidfed/lib/cache"
)

// TestNegativeResolutionDoesNotPersist verifies that a transient failure to fetch
// a subordinate statement (negative result) does not persist due to caching.
// It also guards against the side-effect where an empty trust tree might get cached
// and block subsequent successful resolution with the same resolver inputs.
func TestNegativeResolutionDoesNotPersist(t *testing.T) {
	// Clear relevant caches to avoid cross-test interference
	_ = cache.Clear(cache.Key(cache.KeyEntityStatement))
	_ = cache.Clear(cache.Key(cache.KeyTrustTree))
	_ = cache.Clear(cache.Key(cache.KeyTrustTreeChains))

	// Build a minimal federation: rp -> ia -> ta
	rp := newMockRP("https://rp-negative-cache.example.org", nil)
	ia := newMockAuthority("https://ia-negative-cache.example.org", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-negative-cache.example.org", EntityStatementPayload{})

	ia.RegisterSubordinate(rp)
	ta.RegisterSubordinate(ia)

	// Override the IA's fetch endpoint to fail once, then succeed.
	httpmock.RegisterResponder(
		"GET",
		ia.FetchEndpoint,
		func(req *http.Request) (*http.Response, error) {
			// Return an error response body that matches internal/http.HttpError
			return httpmock.NewJsonResponse(
				500, map[string]any{
					"error":             "server_error",
					"error_description": "transient failure",
				},
			)
		},
	)

	// Resolver with the TA (including its JWKS for signature verification)
	resolver := TrustResolver{
		TrustAnchors: TrustAnchors{
			{
				EntityID: ta.EntityID,
				JWKS:     ta.data.JWKS,
			},
		},
		StartingEntity: rp.EntityID,
	}

	// First attempt should fail to resolve due to the injected fetch error
	chains1 := resolver.ResolveToValidChains()
	if chains1 != nil {
		t.Fatalf("expected no chains on first attempt, got %d", len(chains1))
	}
	httpmock.RegisterResponder(
		"GET",
		ia.FetchEndpoint,
		func(req *http.Request) (*http.Response, error) {
			// Success path: return a properly signed subordinate statement
			sub := req.URL.Query().Get("sub")
			jwt, err := ia.EntityStatementSigner.JWT(ia.SubordinateEntityStatementPayload(sub))
			if err != nil {
				return nil, err
			}
			return httpmock.NewBytesResponse(200, jwt), nil
		},
	)

	// Second attempt with the same inputs must succeed and not be blocked by cache
	// Use a fresh resolver instance with identical parameters to ensure we hit the
	// same cache keys if any negative state persisted.
	resolver2 := TrustResolver{
		TrustAnchors: TrustAnchors{
			{
				EntityID: ta.EntityID,
				JWKS:     ta.data.JWKS,
			},
		},
		StartingEntity: rp.EntityID,
	}
	chains2 := resolver2.ResolveToValidChains()
	if len(chains2) == 0 {
		t.Fatalf("expected chains on second attempt, got none")
	}
	// Basic sanity: ensure the chain ends at the TA we configured
	last := chains2[0][len(chains2[0])-1]
	if last.Issuer != ta.EntityID {
		t.Fatalf("expected chain to end at TA %s, got %s", ta.EntityID, last.Issuer)
	}
}
