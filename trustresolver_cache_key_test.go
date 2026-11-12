package oidfed

import (
	"testing"

	"github.com/go-oidfed/lib/cache"
)

// TestTrustChainCacheKeyIncludesTrustAnchorJWKS verifies that a chain cached
// after verification with one trust anchor JWKS is not returned for the same
// trust anchor entity ID with a different JWKS that does not verify it.
func TestTrustChainCacheKeyIncludesTrustAnchorJWKS(t *testing.T) {
	_ = cache.Clear(cache.Key(cache.KeyEntityStatement))
	_ = cache.Clear(cache.Key(cache.KeyTrustTreeChains))

	rp := newMockRP("https://rp-cache-key.example.org", nil)
	ia := newMockAuthority("https://ia-cache-key.example.org", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-cache-key.example.org", EntityStatementPayload{})
	other := newMockAuthority("https://other-cache-key.example.org", EntityStatementPayload{})
	ia.RegisterSubordinate(rp)
	ta.RegisterSubordinate(ia)

	resolveWith := func(t *testing.T, anchor *mockAuthority) TrustChains {
		t.Helper()
		tas := TrustAnchors{{EntityID: ta.EntityID}}
		tas[0].SetJWKS(anchor.data.JWKS)
		r := TrustResolver{TrustAnchors: tas, StartingEntity: rp.EntityID}
		return r.ResolveToValidChains()
	}

	if chains := resolveWith(t, ta); len(chains) == 0 {
		t.Fatal("expected a chain with the trust anchor's own JWKS")
	}
	if chains := resolveWith(t, other); chains != nil {
		t.Fatalf("expected no chain with an unrelated JWKS for the same trust anchor, got %d", len(chains))
	}
	if chains := resolveWith(t, ta); len(chains) == 0 {
		t.Fatal("expected a chain again with the trust anchor's own JWKS")
	}
}
