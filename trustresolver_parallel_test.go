package oidfed

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-oidfed/lib/cache"
)

// TestTrustResolver_ParallelGraceStopsAtFastBranch verifies that the parallel
// tree build returns with a valid chain from a fast authority instead of
// waiting for a hung sibling authority: the first complete root-to-anchor
// path starts a grace window, after which the remaining (hanging) branch is
// cut off.
func TestTrustResolver_ParallelGraceStopsAtFastBranch(t *testing.T) {
	_ = cache.Clear(cache.Key(cache.KeyEntityStatement))
	_ = cache.Clear(cache.Key(cache.KeyTrustTreeChains))

	rp := newMockRP("https://rp-grace.example.org", nil)
	goodIA := newMockAuthority("https://good-ia-grace.example.org", EntityStatementPayload{})
	hungIA := newMockAuthority("https://hung-ia-grace.example.org", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-grace.example.org", EntityStatementPayload{})

	goodIA.RegisterSubordinate(rp)
	hungIA.RegisterSubordinate(rp)
	ta.RegisterSubordinate(goodIA)

	// Make the hung branch's fetch endpoint block instead of answering.
	httpmock.RegisterResponder("GET", hungIA.FetchEndpoint, func(*http.Request) (*http.Response, error) {
		time.Sleep(30 * time.Second)
		return httpmock.NewBytesResponse(200, []byte("late")), nil
	})

	resolver := TrustResolver{
		TrustAnchors: func() TrustAnchors {
			tas := TrustAnchors{{EntityID: ta.EntityID}}
			tas[0].SetJWKS(ta.data.JWKS)
			return tas
		}(),
		StartingEntity: rp.EntityID,
	}

	start := time.Now()
	chains := resolver.ResolveToValidChains()
	elapsed := time.Since(start)

	require.NotEmpty(t, chains, "expected a chain via goodIA")
	last := chains[0][len(chains[0])-1]
	assert.Equal(t, ta.EntityID, last.Issuer, "chain must be rooted at the configured TA")
	assert.Less(t, elapsed, 5*time.Second, "the hung branch must not delay the resolve beyond the grace cutoff; took %v", elapsed)
}

// TestTrustResolver_InvalidFirstFoundPathDoesNotCut verifies the fix for the
// grace-period correctness concern: a root-to-anchor path that completes
// first but is not usable (here: its metadata policy carries an unknown
// critical operator, so Metadata() fails) must NOT start the grace timer and
// cut off still-running branches. The build must keep going until a valid
// (slower) branch completes and only then stop, returning the valid chain.
//
// Under the old behavior the fast but invalid path closed the found channel,
// the grace (1s) elapsed before the delayed valid branch (1.5s) finished, and
// the resolve returned no chain even though a valid one existed.
func TestTrustResolver_InvalidFirstFoundPathDoesNotCut(t *testing.T) {
	_ = cache.Clear(cache.Key(cache.KeyEntityStatement))
	_ = cache.Clear(cache.Key(cache.KeyTrustTreeChains))

	rp := newMockRP("https://rp-invalid-first.example.org", nil)
	// Fast branch: completes its root-to-anchor path quickly, but its
	// subordinate statement advertises an unsupported critical metadata
	// policy operator, so TrustChain.Metadata() errors -> path not usable.
	fastInvalidIA := newMockAuthority(
		"https://fast-invalid-ia.example.org",
		EntityStatementPayload{MetadataPolicyCrit: []PolicyOperatorName{"remove"}},
	)
	// Slow branch: valid, but completes after the grace period would have
	// elapsed had the fast path wrongly triggered the cutoff.
	goodIA := newMockAuthority("https://good-ia-invalid-first.example.org", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-invalid-first.example.org", EntityStatementPayload{})

	fastInvalidIA.RegisterSubordinate(rp)
	goodIA.RegisterSubordinate(rp)
	ta.RegisterSubordinate(goodIA)
	ta.RegisterSubordinate(fastInvalidIA)

	// Delay the valid branch's fetch so the fast (invalid) branch completes
	// its path first, beyond what the grace period would allow. Return a
	// valid subordinate statement after the delay.
	httpmock.RegisterResponder("GET", goodIA.FetchEndpoint, func(req *http.Request) (*http.Response, error) {
		time.Sleep(1500 * time.Millisecond)
		body, err := goodIA.FetchResponse(req.URL.Query().Get("sub"))
		if err != nil {
			return nil, err
		}
		return httpmock.NewBytesResponse(200, body), nil
	})

	resolver := TrustResolver{
		TrustAnchors: func() TrustAnchors {
			tas := TrustAnchors{{EntityID: ta.EntityID}}
			tas[0].SetJWKS(ta.data.JWKS)
			return tas
		}(),
		StartingEntity: rp.EntityID,
	}

	start := time.Now()
	chains := resolver.ResolveToValidChains()
	elapsed := time.Since(start)

	require.NotEmpty(t, chains, "the invalid fast path must not suppress a valid slower chain")
	last := chains[0][len(chains[0])-1]
	assert.Equal(t, ta.EntityID, last.Issuer, "chain must be rooted at the configured TA via the valid branch")
	assert.Less(t, elapsed, 5*time.Second, "resolve must not wait out the full deadline; took %v", elapsed)
}

// TestTrustResolver_CanceledContextAborts verifies that a canceled resolver
// context aborts resolution quickly instead of walking the tree.
func TestTrustResolver_CanceledContextAborts(t *testing.T) {
	_ = cache.Clear(cache.Key(cache.KeyEntityStatement))
	_ = cache.Clear(cache.Key(cache.KeyTrustTreeChains))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // resolve must not proceed

	rp := newMockRP("https://rp-cancel.example.org", nil)
	ia := newMockAuthority("https://ia-cancel.example.org", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-cancel.example.org", EntityStatementPayload{})
	ia.RegisterSubordinate(rp)
	ta.RegisterSubordinate(ia)

	resolver := TrustResolver{
		TrustAnchors: func() TrustAnchors {
			tas := TrustAnchors{{EntityID: ta.EntityID}}
			tas[0].SetJWKS(ta.data.JWKS)
			return tas
		}(),
		StartingEntity: rp.EntityID,
		Ctx:            ctx,
	}

	start := time.Now()
	chains := resolver.ResolveToValidChains()
	assert.Less(t, time.Since(start), time.Second, "a canceled context must abort resolution quickly")
	assert.Empty(t, chains, "no chains may be produced from a canceled resolution")
}

func TestChainsRootedAt(t *testing.T) {
	ta := &EntityStatement{Issuer: "https://ta.example.org"}
	ia := &EntityStatement{Issuer: "https://ia.example.org"}
	other := &EntityStatement{Issuer: "https://other.example.org"}
	chains := TrustChains{
		TrustChain{ia, ta},
		TrustChain{ia},
		TrustChain{ia, other},
	}

	got := chainsRootedAt(chains, []string{"https://ta.example.org", "https://other.example.org"})
	require.Len(t, got, 2)
	assert.Equal(t, "https://ta.example.org", got[0][len(got[0])-1].Issuer)
	assert.Equal(t, "https://other.example.org", got[1][len(got[1])-1].Issuer)

	require.Empty(t, chainsRootedAt(chains, []string{"https://missing.example.org"}))
	require.Nil(t, chainsRootedAt(chains, nil))
}

func TestTrustResolver_FilterByHintsMode(t *testing.T) {
	ta1 := &EntityStatement{Issuer: "https://ta1.example.org"}
	ta2 := &EntityStatement{Issuer: "https://ta2.example.org"}
	rp := &EntityStatement{Issuer: "https://rp.example.org", TrustAnchorHints: []string{"https://ta1.example.org"}}
	resolver := TrustResolver{
		TrustAnchors: TrustAnchors{
			{EntityID: "https://ta1.example.org"},
			{EntityID: "https://ta2.example.org"},
		},
		trustTree: trustTree{Entity: rp}, // cached resolvers read hints from the built tree
	}
	chains := TrustChains{
		TrustChain{ta1},
		TrustChain{ta2},
	}

	// Prefer: hinted (ta1) chains win when present.
	pref := resolver.filterByHintsMode(TrustAnchorHintsModePrefer, chains)
	require.Len(t, pref, 1)
	assert.Equal(t, "https://ta1.example.org", pref[0][0].Issuer)

	// Require: only hinted chains.
	req := resolver.filterByHintsMode(TrustAnchorHintsModeRequire, chains)
	require.Len(t, req, 1)
	assert.Equal(t, "https://ta1.example.org", req[0][0].Issuer)

	// Ignore: everything is kept.
	assert.Len(t, resolver.filterByHintsMode(TrustAnchorHintsModeIgnore, chains), 2)

	// Require with an empty intersection yields nothing.
	rpNoHints := &EntityStatement{Issuer: "https://rp2.example.org", TrustAnchorHints: []string{"https://other.example.org"}}
	resolver2 := TrustResolver{
		TrustAnchors: resolver.TrustAnchors,
		trustTree:    trustTree{Entity: rpNoHints},
	}
	require.Nil(t, resolver2.filterByHintsMode(TrustAnchorHintsModeRequire, chains))
	require.Len(t, resolver2.filterByHintsMode(TrustAnchorHintsModePrefer, chains), 2)
}
