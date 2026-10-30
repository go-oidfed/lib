package oidfed

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	go2 "github.com/adam-hanna/arrayOperations"
	"github.com/pkg/errors"
	"github.com/scylladb/go-set/strset"
	"github.com/zachmann/go-utils/sliceutils"

	"github.com/go-oidfed/lib/cache"
	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/internal/http"
	"github.com/go-oidfed/lib/internal/jwx"
	"github.com/go-oidfed/lib/internal/utils"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/go-oidfed/lib/unixtime"
)

// TrustAnchorHintsMode controls how the resolver uses
// the starting entity's trust_anchor_hints when selecting
// trust anchors for resolution.
//
//   - Ignore: use configured trust anchors as-is.
//   - Prefer: prefer intersection of configured trust anchors and hints;
//     if intersection is empty, fall back to all configured anchors.
//     Fallback to all configured anchors is handled by callers if
//     intersection does not yield a successful resolve.
//   - Require: use only the intersection of configured trust anchors and hints.
type TrustAnchorHintsMode string

const (
	TrustAnchorHintsModeIgnore  TrustAnchorHintsMode = "ignore"
	TrustAnchorHintsModePrefer  TrustAnchorHintsMode = "prefer"
	TrustAnchorHintsModeRequire TrustAnchorHintsMode = "require"
)

// ResolverCacheGracePeriod is a grace period for the resolver.
// If a cached statement is not yet expired but will expire within that period,
// the cached statement will be used but a fresh statement might be requested in the background (
// see also ResolverCacheLifetimeElapsedGraceFactor).
var ResolverCacheGracePeriod = time.Hour

// ResolverCacheLifetimeElapsedGraceFactor is a factor relevant for the grace period for the resolver.
// If a cached stmt will expire within the ResolverCacheGracePeriod it might be requested in the background before
// expiration. A fresh statement will only be requested if a certain time already has elapsed.
// This factor defines how much time (relative to the total lifetime of that statement) must have elapsed so that the
// statement is refreshed. E.g. a factor of 0.
// 75 means that a statement will only be refreshed if the statement expires within the ResolverCacheGracePeriod and
// 75% of the statement's lifetime already have elapsed.
// The purpose of this factor is to allow a bigger ResolverCacheGracePeriod and still deal with smaller statement
// lifetimes.
var ResolverCacheLifetimeElapsedGraceFactor = 0.5

// ResolveResponse is a type describing the response of a resolve request
type ResolveResponse struct {
	Issuer                 string            `json:"iss"`
	Subject                string            `json:"sub"`
	IssuedAt               unixtime.Unixtime `json:"iat"`
	ExpiresAt              unixtime.Unixtime `json:"exp"`
	Audience               string            `json:"aud,omitempty"`
	ResolveResponsePayload `json:",inline"`
}

// MarshalJSON implements the json.Marshaler interface.
// It also marshals extra fields.
func (r ResolveResponse) MarshalJSON() ([]byte, error) {
	payload, err := r.ResolveResponsePayload.MarshalJSON()
	if err != nil {
		return nil, err
	}
	type additionalData struct {
		Issuer    string            `json:"iss"`
		Subject   string            `json:"sub"`
		IssuedAt  unixtime.Unixtime `json:"iat"`
		ExpiresAt unixtime.Unixtime `json:"exp"`
		Audience  string            `json:"aud,omitempty"`
	}
	additional, err := json.Marshal(
		additionalData{
			Issuer:    r.Issuer,
			Subject:   r.Subject,
			IssuedAt:  r.IssuedAt,
			ExpiresAt: r.ExpiresAt,
			Audience:  r.Audience,
		},
	)
	if err != nil {
		return nil, err
	}
	additional[0] = ','
	return extraMarshalHelper(append(payload[:len(payload)-1], additional...), r.Extra)
}

// ResolveResponsePayload holds the actual payload of a resolve response
type ResolveResponsePayload struct {
	Metadata    *Metadata      `json:"metadata,omitempty"`
	TrustMarks  TrustMarkInfos `json:"trust_marks,omitempty"`
	TrustChain  JWSMessages    `json:"trust_chain,omitempty"`
	TrustAnchor string         `json:"trust_anchor,omitempty"`
	// ValidUntil bounds how long this result is valid: the earliest
	// statement expiry of the resolved trust chain (local resolution) or the
	// resolve response's exp claim (remote resolution). It is not
	// serialized; callers (e.g. caching) use it to bound how long the
	// payload may be kept.
	ValidUntil unixtime.Unixtime `json:"-"`
	Extra      map[string]any    `json:"-"`
}

// MarshalJSON implements the json.Marshaler interface.
// It also marshals extra fields.
func (r ResolveResponsePayload) MarshalJSON() ([]byte, error) {
	type Alias ResolveResponsePayload
	explicitFields, err := json.Marshal(Alias(r))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, r.Extra)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It also unmarshalls additional fields into the Extra claim.
func (r *ResolveResponsePayload) UnmarshalJSON(data []byte) error {
	type Alias ResolveResponsePayload
	var rr Alias
	extra, err := unmarshalWithExtra(data, &rr)
	if err != nil {
		return err
	}
	rr.Extra = extra
	*r = ResolveResponsePayload(rr)
	return nil
}

// JWSMessages is a slices of jwx.ParseJWT
type JWSMessages []*jwx.ParsedJWT

// MarshalJSON implements the json.Marshaler interface.
func (m JWSMessages) MarshalJSON() ([]byte, error) {
	jwts := make([]string, len(m))
	for i, mm := range m {
		jwts[i] = string(mm.RawJWT)
	}
	return json.Marshal(jwts)
}

// UnmarshalJSON implements the json.Marshaler interface.
func (m *JWSMessages) UnmarshalJSON(data []byte) error {
	var datas []string
	if err := json.Unmarshal(data, &datas); err != nil {
		return err
	}
	for _, d := range datas {
		jwt, err := jwx.Parse([]byte(d))
		if err != nil {
			return err
		}
		*m = append(*m, jwt)
	}
	return nil
}

// TrustResolver is type for resolving trust chains from a StartingEntity to one or multiple TrustAnchors
type TrustResolver struct {
	TrustAnchors   TrustAnchors
	StartingEntity string
	Types          []string
	// Ctx, when non-nil, bounds and cancels the resolution (request deadline
	// or client disconnect). A default deadline is applied when none is set.
	Ctx                  context.Context
	trustTree            trustTree
	TrustAnchorHintsMode TrustAnchorHintsMode
	selectedAnchors      []string
}

func (r TrustResolver) hash() (string, error) {
	tas := make([]string, len(r.TrustAnchors))
	for i, ta := range r.TrustAnchors {
		tas[i] = ta.EntityID
	}
	var forSerialization = struct {
		StartingEntity string
		TAs            []string
		Types          []string
		Mode           TrustAnchorHintsMode
	}{
		StartingEntity: r.StartingEntity,
		TAs:            tas,
		Types:          r.Types,
		Mode:           r.TrustAnchorHintsMode,
	}
	return utils.HashStruct(forSerialization)
}

// ResolveToValidChains starts the trust chain resolution process, building an internal trust tree,
// verifies the signatures, integrity, expirations, and metadata policies and returns all possible valid TrustChains
func (r *TrustResolver) ResolveToValidChains() TrustChains {
	chains := r.ResolveToValidChainsWithoutVerifyingMetadata()
	if chains == nil {
		return nil
	}
	return chains.Filter(TrustChainsFilterValidMetadata)
}

// ResolveToValidChainsWithoutVerifyingMetadata starts the trust chain
// resolution process, building an internal trust tree,
// verifies the signatures, integrity, expirations,
// but not metadata policies and returns all possible valid TrustChains
func (r *TrustResolver) ResolveToValidChainsWithoutVerifyingMetadata() TrustChains {
	// Build the trust tree at most once per call — against all configured
	// trust anchors — and then narrow the resulting chains by the trust
	// anchor hints mode. The tree build explores every authority hint of the
	// starting entity regardless of which anchors are configured or hinted,
	// so the fetched set is identical no matter the mode; only the
	// verification root set (here: all configured anchors) and the final
	// narrow-by-hints filter differ. The old double pass (build for Require,
	// rebuild for Ignore when the first yielded nothing) therefore rebuilt
	// and re-verified the same tree a second time for no benefit, and the
	// second build's only saving (requiring a hinted anchor) is recovered
	// here as a pure in-memory filter over the already-built chains.
	mode := r.hintsMode()
	r.TrustAnchorHintsMode = TrustAnchorHintsModeIgnore

	chains, set, err := r.cacheGetTrustChains()
	if err != nil {
		set = false
		internal.Log("TrustResolver: " + err.Error())
	}
	if set {
		internal.Log("TrustResolver: Obtained trust chains from cache")
	} else {
		internal.Log("TrustResolver: Trust chains cache miss; resolving trust tree and verifying signatures")
		r.resolve()
		r.verifySignatures()
		chains = r.chains()
	}
	if len(chains) == 0 {
		return nil
	}
	return r.filterByHintsMode(mode, chains)
}

// hintsMode returns the effective trust anchor hints mode, normalizing "" and
// Prefer to Prefer: both prefer hinted anchors first and fall back to all
// configured anchors.
func (r TrustResolver) hintsMode() TrustAnchorHintsMode {
	if r.TrustAnchorHintsMode == TrustAnchorHintsModeRequire {
		return TrustAnchorHintsModeRequire
	}
	return TrustAnchorHintsModePrefer
}

// startingHints returns the trust anchor hints of the starting entity, from
// the built tree when available, otherwise by fetching the starting entity's
// entity configuration (cached).
func (r TrustResolver) startingHints() []string {
	if r.trustTree.Entity != nil {
		return r.trustTree.Entity.TrustAnchorHints
	}
	if r.StartingEntity == "" {
		return nil
	}
	ctx, cancel := r.buildContext()
	defer cancel()
	starting, err := GetEntityConfigurationCtx(ctx, r.StartingEntity)
	if err != nil {
		return nil
	}
	return starting.TrustAnchorHints
}

// filterByHintsMode narrows already-resolved chains to the roots the given
// hint mode accepts, without rebuilding the tree: Require keeps only chains
// rooted at the intersection of the starting entity's hints and the
// configured anchors, Prefer prefers those (falling back to all chains), and
// Ignore keeps everything.
func (r TrustResolver) filterByHintsMode(mode TrustAnchorHintsMode, chains TrustChains) TrustChains {
	if mode != TrustAnchorHintsModeRequire && mode != TrustAnchorHintsModePrefer {
		return chains
	}
	hints := r.startingHints()
	if len(hints) == 0 {
		return chains
	}
	intersection := go2.Intersect(hints, r.TrustAnchors.EntityIDs())
	if mode == TrustAnchorHintsModeRequire {
		if len(intersection) == 0 {
			return nil
		}
		return chainsRootedAt(chains, intersection)
	}
	// Prefer
	if len(intersection) > 0 {
		if preferred := chainsRootedAt(chains, intersection); len(preferred) > 0 {
			return preferred
		}
	}
	return chains
}

// chainsRootedAt returns the chains whose final statement (the trust
// anchor's entity configuration) is issued by one of tAs.
func chainsRootedAt(chains TrustChains, tAs []string) TrustChains {
	if len(tAs) == 0 {
		return nil
	}
	roots := make(map[string]struct{}, len(tAs))
	for _, id := range tAs {
		roots[id] = struct{}{}
	}
	out := make(TrustChains, 0, len(chains))
	for _, c := range chains {
		if len(c) == 0 {
			continue
		}
		if _, ok := roots[c[len(c)-1].Issuer]; ok {
			out = append(out, c)
		}
	}
	return out
}

// resolve starts the trust chain resolution process, building an internal trust tree
func (r *TrustResolver) resolve() {
	if r.StartingEntity == "" {
		internal.Log("TrustResolver: Resolve: no StartingEntity provided; aborting")
		return
	}
	ctx, cancel := r.buildContext()
	defer cancel()

	starting, err := GetEntityConfigurationCtx(ctx, r.StartingEntity)
	if err != nil {
		internal.Logf(
			"TrustResolver: Resolve: failed to get starting entity configuration for %s: %v", r.StartingEntity, err,
		)
		return
	}
	if len(r.Types) > 0 {
		utils.NilAllExceptByTag(starting.Metadata, r.Types)
		internal.Logf("TrustResolver: Resolve: constrained metadata to types: %v", r.Types)
	}
	var entityTypes []string
	if starting.Metadata != nil {
		entityTypes = starting.Metadata.GuessEntityTypes()
	}
	build := &trustBuild{
		ctx:     ctx,
		cancel:  cancel,
		sem:     make(chan struct{}, maxConcurrentResolverCandidates),
		allDone: make(chan struct{}),
		found:   make(chan struct{}),
		grace:   defaultParallelResolveGrace,
		anchors: r.TrustAnchors,
	}
	r.trustTree = trustTree{
		Entity:              starting,
		includedEntityTypes: strset.New(entityTypes...),
		subordinateIDs:      strset.New(starting.Subject),
		build:               build,
	}
	r.selectedAnchors = r.chooseAnchors(starting)
	r.trustTree.resolve(r.selectedAnchors)
	r.awaitBuild(build)
}

// buildContext returns the resolution context: the caller's context, always
// wrapped so the resolver can cancel it, and bounded by
// defaultParallelResolveDeadline when the caller provided none.
func (r TrustResolver) buildContext() (context.Context, context.CancelFunc) {
	parent := r.Ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	ctx, deadlineCancel := context.WithTimeout(ctx, defaultParallelResolveDeadline)
	return ctx, func() {
		cancel()
		deadlineCancel()
	}
}

// awaitBuild runs the parallel build until it should stop: when the whole
// tree has been built, shortly (grace period) after the first complete
// root-to-anchor path was found, or when the deadline expires. On stop it
// cancels the build context so remaining workers are aborted, then waits for
// them to drain so the tree is safe to verify. A build cut short by the
// grace/deadline is marked incomplete so it is not cached as if complete.
func (r *TrustResolver) awaitBuild(b *trustBuild) {
	// A build with no workers never reaches pending zero via a worker; an
	// idle build is trivially complete.
	if b.pending.Load() == 0 {
		b.complete = true
		return
	}
	select {
	case <-b.allDone:
		// The whole tree was built; nothing left to wait for.
		b.complete = true
	case <-b.found:
		// First complete path found; give still-running branches a grace
		// window to yield a better (shorter) chain, then cut them off.
		select {
		case <-time.After(b.grace):
		case <-b.ctx.Done():
		case <-b.allDone:
		}
		if b.pending.Load() == 0 {
			b.complete = true
		}
		b.cancel()
		<-b.allDone
	case <-b.ctx.Done():
		// Deadline (caller-provided or default) expired.
		b.cancel()
		<-b.allDone
	}
}

// chooseAnchors selects which trust anchors to use based on the provided
// starting entity configuration and the resolver's TrustAnchorHintsMode.
// Default mode is Prefer when unset.
func (r TrustResolver) chooseAnchors(starting *EntityStatement) []string {
	configured := r.TrustAnchors.EntityIDs()
	mode := r.TrustAnchorHintsMode
	if mode == "" || mode == TrustAnchorHintsModePrefer {
		internal.Error("internal error: TrustAnchorHintsMode not set or set to Prefer; should never happen")
		return configured
	}
	hints := starting.TrustAnchorHints
	if len(hints) == 0 || mode == TrustAnchorHintsModeIgnore {
		return configured
	}
	intersection := go2.Intersect(hints, configured)
	if mode == TrustAnchorHintsModeRequire {
		return intersection
	}
	// Prefer mode: if intersection non-empty, use it; else use configured
	if len(intersection) > 0 {
		return intersection
	}
	return configured
}

// verifySignatures verifies the signatures of the internal trust tree
func (r *TrustResolver) verifySignatures() {
	// Determine anchors to use for signature verification in line with the
	// chosen TrustAnchorHintsMode. Compute dynamically from current trust tree.
	anchorsToUse := r.TrustAnchors
	if r.trustTree.Entity != nil {
		ids := r.chooseAnchors(r.trustTree.Entity)
		if len(ids) > 0 {
			// filter anchors to the chosen ids, preserving order from ids
			idset := make(map[string]struct{}, len(ids))
			for _, id := range ids {
				idset[id] = struct{}{}
			}
			var filtered TrustAnchors
			for _, id := range ids {
				for _, ta := range r.TrustAnchors {
					if ta.EntityID == id {
						filtered = append(filtered, ta)
						break
					}
				}
			}
			anchorsToUse = filtered
		} else if r.TrustAnchorHintsMode == TrustAnchorHintsModeRequire {
			// Require mode with empty intersection => no anchors
			anchorsToUse = nil
		}
	}
	if !r.trustTree.verifySignatures(anchorsToUse) {
		internal.Log("TrustResolver: VerifySignatures: signature verification failed; clearing trust tree")
		r.trustTree = trustTree{}
	}
	if r.trustTree.signaturesVerified {
		internal.Logf(
			"TrustResolver: VerifySignatures: signature verification succeeded; valid authorities at root: %d",
			len(r.trustTree.Authorities),
		)
	}
}

// chains returns the TrustChains in the internal trust tree
func (r TrustResolver) chains() (chains TrustChains) {
	chains, set, err := r.cacheGetTrustChains()
	if err != nil {
		internal.Log("TrustResolver: " + err.Error())
	}
	if set {
		return chains
	}
	chains = r.trustTree.chains()
	if chains == nil {
		internal.Log("TrustResolver: Chains: no chains found from current trust tree")
		return nil
	}
	if r.trustTree.build == nil || r.trustTree.build.complete {
		if err = r.cacheSetTrustChains(chains); err != nil {
			internal.Log("TrustResolver: " + err.Error())
		}
		internal.Logf("TrustResolver: Chains: computed %d chain(s) and cached them", len(chains))
	} else {
		internal.Logf(
			"TrustResolver: Chains: computed %d chain(s); build was cut short, not caching",
			len(chains),
		)
	}
	return
}

func (r TrustResolver) cacheGetTrustChains() (
	chains TrustChains, set bool, err error,
) {
	hash, err := r.hash()
	if err != nil {
		return nil, false, err
	}
	set, err = cache.Get(
		cache.Key(cache.KeyTrustTreeChains, hash), &chains,
	)
	return
}

func (r TrustResolver) cacheSetTrustChains(chains TrustChains) error {
	hash, err := r.hash()
	if err != nil {
		return err
	}
	ttl := unixtime.Until(chains.MinExpiresAt())
	internal.Logf("TrustResolver: Caching trust chains with TTL %s (hash:%s)", ttl, hash)
	return cache.Set(
		cache.Key(cache.KeyTrustTreeChains, hash), chains,
		ttl,
	)
}

// trustTree is a type for holding EntityStatements in a tree
type trustTree struct {
	Entity              *EntityStatement
	Subordinate         *EntityStatement
	Authorities         []trustTree
	signaturesVerified  bool
	depth               int
	includedEntityTypes *strset.Set
	subordinateIDs      *strset.Set
	// parent links a node to its ancestor in the tree (nil for the root). It
	// lets the build assemble a complete root-to-anchor chain from a leaf
	// (see trustTree.chainToRoot) so a found path can be checked for
	// signature and metadata validity before the grace period is started.
	parent *trustTree
	// build carries the per-resolution build state (context, concurrency
	// cap, stop-on-success signaling) shared by every node of the tree.
	build *trustBuild
}

// trustBuild is the shared, per-resolution state of a parallel trust tree
// build: a cancellable context (caller context + deadline), a concurrency cap
// for the parallel statement fetches, and a signal that fires once a complete
// root-to-anchor path has been found so the build can stop exploring further
// branches after a grace period instead of always walking the whole tree.
type trustBuild struct {
	ctx     context.Context
	cancel  context.CancelFunc
	sem     chan struct{}
	pending atomic.Int64
	allDone chan struct{}
	// allDoneOnce guards closing allDone, which happens once the last worker
	// has finished (pending reached zero).
	allDoneOnce sync.Once
	found       chan struct{}
	foundOnce   sync.Once
	grace       time.Duration
	// anchors are the configured trust anchors (with keys) used to verify the
	// signatures of a found root-to-anchor path before the build may cut off
	// its remaining branches after the grace period.
	anchors TrustAnchors
	// complete reports whether the whole tree was built (as opposed to being
	// cut short by the grace/deadline stop). Incomplete trees must not be
	// cached as if they were complete.
	complete bool
}

// begin is called before spawning a worker; it registers the worker so the
// build knows it is not idle. Workers Add their nested workers synchronously
// before finishing, so pending can only reach zero once every worker — at
// every tree depth — has finished.
func (b *trustBuild) begin() {
	b.pending.Add(1)
}

// finish is deferred by every worker; the last one closes allDone.
func (b *trustBuild) finish() {
	if b.pending.Add(-1) == 0 {
		b.allDoneOnce.Do(func() { close(b.allDone) })
	}
}

// signalFound records that a complete root-to-anchor path exists in the tree.
func (b *trustBuild) signalFound() {
	b.foundOnce.Do(func() { close(b.found) })
}

func (t *trustTree) resolve(anchors []string) {
	if t.Entity == nil || t.build == nil || t.build.ctx.Err() != nil {
		return
	}

	// Early return if the entity is issued by a trust anchor; a complete
	// root-to-anchor path exists. The build must not treat it as a stop
	// unless the path is actually usable: if its signatures do not verify or
	// its metadata does not resolve, signaling here would let the grace
	// period cut off still-running branches that might yield a valid chain.
	// foundPathValid checks exactly that, so an invalid first path keeps the
	// build running (the found channel stays open for a later valid path).
	if sliceutils.SliceContains(t.Entity.Issuer, anchors) {
		if t.foundPathValid(t.build.anchors) {
			internal.Logf(
				"TrustResolver: resolve: valid root-to-anchor path at entity %s issued by trust anchor; early return",
				t.Entity.Issuer,
			)
			t.build.signalFound()
		} else {
			internal.Logf(
				"TrustResolver: resolve: root-to-anchor path at entity %s issued by trust anchor is invalid; continuing build",
				t.Entity.Issuer,
			)
		}
		return
	}

	t.resolveAuthorities(anchors)
}

// resolveAuthorities resolves all authority hints of t concurrently (capped
// by the shared build semaphore). Each worker writes a distinct Authorities
// index, which is safe; the tree is only read after all workers have drained
// (see TrustResolver.awaitBuild).
func (t *trustTree) resolveAuthorities(anchors []string) {
	if len(t.Entity.AuthorityHints) > 0 {
		t.Authorities = make([]trustTree, len(t.Entity.AuthorityHints))
	}

	internal.Logf(
		"TrustResolver: resolveAuthorities: %d authority hint(s) for entity %s at depth %d",
		len(t.Entity.AuthorityHints), t.Entity.Issuer, t.depth,
	)
	for i, authorityID := range t.Entity.AuthorityHints {
		if t.subordinateIDs.Has(authorityID) {
			internal.Logf(
				"TrustResolver: resolveAuthorities: skipping authority %s due to loop prevention", authorityID,
			)
			continue // Loop prevention
		}
		if t.build.ctx.Err() != nil {
			return
		}
		t.build.begin()
		go func() {
			defer t.build.finish()
			select {
			case t.build.sem <- struct{}{}:
			case <-t.build.ctx.Done():
				return
			}
			defer func() { <-t.build.sem }()
			if t.build.ctx.Err() != nil {
				return
			}
			authority, err := t.resolveAuthority(authorityID, anchors)
			if err != nil {
				internal.Logf("TrustResolver: resolveAuthorities: failed resolving authority %s: %v", authorityID, err)
				return
			}
			t.Authorities[i] = authority
		}()
	}
}

func (t *trustTree) resolveAuthority(authorityID string, anchors []string) (trustTree, error) {
	authorityStmt, err := GetEntityConfigurationCtx(t.build.ctx, authorityID)
	if err != nil {
		internal.Logf("TrustResolver: resolveAuthority: failed to obtain authority EC for %s: %v", authorityID, err)
		return trustTree{}, err
	}

	if !isValidAuthorityStatement(authorityStmt, authorityID) {
		// Try to provide details why it's invalid
		if !(utils.Equal(authorityStmt.Issuer, authorityStmt.Subject, authorityID)) {
			internal.Logf(
				"TrustResolver: resolveAuthority: invalid authority statement for %s: issuer/subject mismatch (iss=%s sub=%s)",
				authorityID, authorityStmt.Issuer, authorityStmt.Subject,
			)
		}
		if !authorityStmt.TimeValid() {
			internal.Logf(
				"TrustResolver: resolveAuthority: invalid authority statement for %s: not time-valid (iat=%v exp=%v)",
				authorityID,
				authorityStmt.IssuedAt, authorityStmt.ExpiresAt,
			)
		}
		if authorityStmt.Metadata == nil || authorityStmt.Metadata.FederationEntity == nil {
			internal.Logf(
				"TrustResolver: resolveAuthority: invalid authority statement for %s: missing federation_entity metadata",
				authorityID,
			)
		} else if authorityStmt.Metadata.FederationEntity.FederationFetchEndpoint == "" {
			internal.Logf(
				"TrustResolver: resolveAuthority: invalid authority statement for %s: missing federation_fetch_endpoint",
				authorityID,
			)
		}
		return trustTree{}, errors.New("invalid authority statement")
	}
	internal.Logf(
		"TrustResolver: resolveAuthority: authority statement valid for %s; fetch endpoint: %s", authorityID,
		authorityStmt.Metadata.FederationEntity.FederationFetchEndpoint,
	)

	subordinateStmt, err := t.fetchAndValidateSubordinateStatement(authorityStmt, authorityID)
	if err != nil {
		internal.Logf(
			"TrustResolver: resolveAuthority: failed to fetch/validate subordinate stmt for %s->%s: %v", authorityID,
			t.Entity.Issuer,
			err,
		)
		return trustTree{}, err
	}
	internal.Logf(
		"TrustResolver: resolveAuthority: subordinate statement valid for authority %s and subordinate %s", authorityID,
		t.Entity.Issuer,
	)

	if !t.checkConstraints(subordinateStmt.Constraints) {
		internal.Logf(
			"TrustResolver: resolveAuthority: constraints check failed for authority %s and subordinate %s",
			authorityID,
			t.Entity.Issuer,
		)
		return trustTree{}, errors.New("constraints check failed")
	}
	internal.Logf(
		"TrustResolver: resolveAuthority: constraints satisfied for authority %s and subordinate %s", authorityID,
		t.Entity.Issuer,
	)

	subtree := t.createAuthorityTrustTree(authorityStmt, subordinateStmt, authorityID, anchors)
	internal.Logf(
		"TrustResolver: resolveAuthority: created subtree for authority %s at depth %d (authorities: %d)", authorityID,
		subtree.depth, len(subtree.Authorities),
	)
	return subtree, nil
}

func isValidAuthorityStatement(stmt *EntityStatement, authorityID string) bool {
	return utils.Equal(stmt.Issuer, stmt.Subject, authorityID) &&
		stmt.TimeValid() &&
		stmt.Metadata != nil &&
		stmt.Metadata.FederationEntity != nil &&
		stmt.Metadata.FederationEntity.FederationFetchEndpoint != ""
}

func (t *trustTree) fetchAndValidateSubordinateStatement(
	authorityStmt *EntityStatement, authorityID string,
) (*EntityStatement, error) {
	subordinateStmt, err := FetchEntityStatementCtx(
		t.build.ctx,
		authorityStmt.Metadata.FederationEntity.FederationFetchEndpoint, t.Entity.Issuer, authorityID,
		authorityStmt.Metadata.FederationEntity,
	)
	if err != nil {
		return nil, err
	}

	if !isValidSubordinateStatement(subordinateStmt, authorityID, t.Entity.Issuer) {
		return nil, errors.New("invalid subordinate statement")
	}

	return subordinateStmt, nil
}

func isValidSubordinateStatement(stmt *EntityStatement, authorityID, entityIssuer string) bool {
	return stmt.Issuer == authorityID &&
		stmt.Subject == entityIssuer &&
		stmt.TimeValid()
}

func (t *trustTree) createAuthorityTrustTree(
	authorityStmt, subordinateStmt *EntityStatement, authorityID string, anchors []string,
) trustTree {
	entityTypes := t.includedEntityTypes.Copy()
	entityTypes.Add(authorityStmt.Metadata.GuessEntityTypes()...)

	subordinates := t.subordinateIDs.Copy()
	subordinates.Add(authorityID)

	newTree := trustTree{
		Entity:              authorityStmt,
		Subordinate:         subordinateStmt,
		depth:               t.depth + 1,
		includedEntityTypes: entityTypes,
		subordinateIDs:      subordinates,
		parent:              t,
		build:               t.build,
	}
	newTree.resolve(anchors)

	return newTree
}

func (t *trustTree) checkConstraints(constraints *ConstraintSpecification) bool {
	if constraints == nil {
		return true
	}
	internal.Logf("TrustResolver: checking constraints %+v...", constraints)
	if constraints.MaxPathLength != nil && *constraints.MaxPathLength < t.depth {
		internal.Log("TrustResolver: max path len constraint failed")
		return false
	}
	internal.Log("TrustResolver: max path len constraint succeeded")
	if naming := constraints.NamingConstraints; naming != nil {
		internal.Logf("TrustResolver: checking naming constraints %+v", naming)
		for _, id := range t.subordinateIDs.List() {
			if slices.ContainsFunc(
				naming.Excluded, func(e string) bool {
					return matchNamingConstraint(e, id)
				},
			) {
				internal.Log("TrustResolver: naming constraint failed")
				return false
			}
			if naming.Permitted == nil {
				continue
			}
			if slices.ContainsFunc(
				naming.Permitted, func(e string) bool {
					return matchNamingConstraint(e, id)
				},
			) {
				continue
			}
			internal.Log("TrustResolver: naming constraint failed")
			return false
		}
	}
	internal.Log("TrustResolver: naming constraint succeeded")
	if constraints.AllowedEntityTypes != nil {
		allowed := strset.New(append(constraints.AllowedEntityTypes, "federation_entity")...)
		forbidden := strset.Difference(t.includedEntityTypes, allowed)
		if !forbidden.IsEmpty() {
			internal.Log("TrustResolver: entity type constraint failed")
			return false
		}
	}
	internal.Log("TrustResolver: entity types constraint succeeded")
	return true
}

func matchNamingConstraint(constraint, id string) bool {
	u, err := url.Parse(id)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if strings.HasPrefix(constraint, ".") {
		return strings.HasSuffix(host, constraint)
	}
	return constraint == host
}

func (t *trustTree) verifySignatures(anchors TrustAnchors) bool {
	if t.signaturesVerified {
		return true
	}
	if t.Entity == nil {
		return false
	}
	if t.Entity.Issuer == t.Entity.Subject {
		for _, ta := range anchors {
			if ta.EntityID == t.Entity.Issuer {
				// t is about a TA
				jwks := ta.JWKS()
				if jwks.Set == nil {
					jwks = t.Entity.JWKS
				}
				t.signaturesVerified = t.Entity.Verify(jwks)
				if t.signaturesVerified && t.Subordinate != nil {
					t.signaturesVerified = t.Subordinate.Verify(jwks)
				}
				return t.signaturesVerified
			}
		}
	}
	iValid := 0
	for _, tt := range t.Authorities {
		if !tt.verifySignatures(anchors) {
			continue
		}
		// the tt is trusted, getting the JWKS to verify our own signatures
		jwks := tt.Subordinate.JWKS
		if !t.Entity.Verify(jwks) {
			continue
		}
		if t.Subordinate != nil && !t.Subordinate.Verify(jwks) {
			continue
		}
		t.Authorities[iValid] = tt
		iValid++
	}
	t.Authorities = t.Authorities[:iValid]
	t.signaturesVerified = len(t.Authorities) > 0
	return t.signaturesVerified
}

// foundPathValid reports whether the complete root-to-anchor path ending at
// t is usable: its signatures verify against the configured anchors and its
// metadata resolves. The signature check reuses the authoritative tree
// verifier on an isolated single-path reconstruction of t's chain, so it is
// consistent with the full-tree verification that runs after the build; the
// metadata check is the same predicate (TrustChain.Metadata succeeds) that
// TrustChainsFilterValidMetadata applies later.
func (t *trustTree) foundPathValid(anchors TrustAnchors) bool {
	chain := t.chainToRoot()
	if len(chain) == 0 {
		return false
	}
	if !trustTreeFromChain(chain).verifySignatures(anchors) {
		return false
	}
	_, err := chain.Metadata()
	return err == nil
}

// trustTreeFromChain reconstructs a minimal single-path trust tree from a
// root-to-leaf chain produced by trustTree.chainToRoot, so verifySignatures
// can be reused on just that path. The chain alternates an entity
// configuration and a subordinate statement: [rootEC, sb1, ec1, ..., sbN,
// ecN]; the reconstructed root has no subordinate statement and every deeper
// node carries its Subordinate and Entity, mirroring the real tree nodes.
func trustTreeFromChain(c TrustChain) *trustTree {
	if len(c) == 0 {
		return &trustTree{}
	}
	if len(c) == 1 {
		return &trustTree{Entity: c[0]}
	}
	nodes := make([]*trustTree, (len(c)-1)/2+1)
	// Deepest (leaf) node: Entity is the last element, Subordinate before it.
	nodes[len(nodes)-1] = &trustTree{Entity: c[len(c)-1], Subordinate: c[len(c)-2]}
	for i := len(nodes) - 2; i >= 0; i-- {
		// Node i's (Subordinate, Entity) pair lives at chain indices 2*i+1, 2*i+2.
		nodes[i] = &trustTree{
			Entity:      c[2*i+2],
			Subordinate: c[2*i+1],
			Authorities: []trustTree{*nodes[i+1]},
		}
	}
	// Root has no subordinate statement; its Entity heads the chain.
	nodes[0].Subordinate = nil
	return nodes[0]
}

func (t trustTree) chains() (chains []TrustChain) {
	if t.Authorities == nil {
		if t.Subordinate == nil {
			if t.Entity == nil {
				return nil
			}
			return []TrustChain{
				{
					t.Entity,
				},
			}
		}
		return []TrustChain{
			{
				t.Subordinate,
				t.Entity,
			},
		}
	}
	for _, a := range t.Authorities {
		toAppend := t.Subordinate
		if toAppend == nil {
			toAppend = t.Entity
		}
		for _, aChain := range a.chains() {
			chains = append(chains, append(TrustChain{toAppend}, aChain...))
		}
	}
	return
}

// chainToRoot assembles the full root-to-this-node trust chain in the same
// ordering trustTree.chains produces for a single path: the root's entity
// configuration, then for each ancestor (moving toward this node) the
// subordinate statement issued by that ancestor about the next-lower entity
// followed by the ancestor's own entity configuration. The node's parent
// pointers must form a path back to the root.
func (t trustTree) chainToRoot() TrustChain {
	var path []*trustTree
	for n := &t; n != nil; n = n.parent {
		path = append(path, n)
	}
	// path is leaf-first (t, ..., root); walk it root-first to build the
	// chain in root-to-leaf order.
	chain := TrustChain{path[len(path)-1].Entity} // root.Entity heads the chain
	for i := len(path) - 2; i >= 0; i-- {
		n := path[i]
		chain = append(chain, n.Subordinate, n.Entity)
	}
	return chain
}

func entityStmtCacheSet(subID, issID string, stmt *EntityStatement) {
	if err := cache.Set(
		cache.EntityStmtCacheKey(subID, issID), stmt, time.Until(stmt.ExpiresAt.Time),
	); err != nil {
		internal.Log(err)
	}
}
func entityStmtCacheGet(subID, issID string) *EntityStatement {
	var stmt EntityStatement
	set, err := cache.Get(cache.EntityStmtCacheKey(subID, issID), &stmt)
	if err != nil {
		internal.Log(err)
		return nil
	}
	if !set {
		return nil
	}
	return &stmt
}

// GetEntityConfiguration obtains the entity configuration for the passed entity id and returns it as an
// EntityStatement
func GetEntityConfiguration(entityID string) (*EntityStatement, error) {
	return GetEntityConfigurationCtx(context.Background(), entityID)
}

// GetEntityConfigurationCtx is GetEntityConfiguration with a context; the
// fetch (and, for the synchronous path, nothing else) can be canceled via
// ctx. The background cache-grace refresh is intentionally detached from ctx.
func GetEntityConfigurationCtx(ctx context.Context, entityID string) (*EntityStatement, error) {
	return getEntityStatementOrConfigurationCtx(
		ctx, entityID, entityID, func(ctx context.Context) (*EntityStatement, error) {
			return httpGetEntityConfigurationCtx(ctx, entityID)
		},
	)
}

func getEntityStatementOrConfigurationCtx(
	ctx context.Context, subID, issID string, obtainerFnc func(context.Context) (*EntityStatement, error),
) (*EntityStatement, error) {

	if stmt := entityStmtCacheGet(subID, issID); stmt != nil {
		internal.Log("TrustResolver: Obtained entity statement from cache")
		go func() {
			remainingLifetime := time.Until(stmt.ExpiresAt.Time)
			totalLifetime := stmt.ExpiresAt.Sub(stmt.IssuedAt.Time)
			if remainingLifetime <= ResolverCacheGracePeriod && float64(remainingLifetime)/float64(totalLifetime) > ResolverCacheLifetimeElapsedGraceFactor {
				internal.Log("TrustResolver: Within grace period, refreshing entity statement")
				_, err := obtainAndSetEntityStatementOrConfiguration(
					subID,
					issID, func() (*EntityStatement, error) {
						// The background refresh must outlive the caller.
						return obtainerFnc(context.Background())
					},
				)
				if err != nil {
					internal.Log("TrustResolver: ", err)
				}
			}
		}()
		return stmt, nil
	}
	return obtainAndSetEntityStatementOrConfiguration(
		subID, issID, func() (*EntityStatement, error) {
			return obtainerFnc(ctx)
		},
	)
}

func obtainAndSetEntityStatementOrConfiguration(
	subID, issID string, obtainerFnc func() (*EntityStatement, error),
) (*EntityStatement, error) {
	stmt, err := obtainerFnc()
	if err != nil {
		internal.Log(err)
		return nil, err
	}
	internal.Log("TrustResolver: Obtained entity statement from http")
	entityStmtCacheSet(subID, issID, stmt)
	return stmt, nil
}

func httpGetEntityConfigurationCtx(
	ctx context.Context, entityID string,
) (*EntityStatement, error) {
	uri := strings.TrimSuffix(entityID, "/") + oidfedconst.FederationSuffix
	internal.Logf("TrustResolver: Obtaining entity configuration from %+q", uri)
	res, errRes, err := http.GetCtx(ctx, uri, nil, nil)
	if err != nil {
		return nil, err
	}
	if errRes != nil {
		return nil, errRes.Err()
	}
	return ParseEntityStatement(res.Body())
}

// FetchEntityStatementCtx fetches an EntityStatement from a fetch endpoint,
// honoring ctx for cancellation. When the given federation entity metadata
// advertises private_key_jwt in federation_fetch_endpoint_auth_methods and
// DefaultClientAuth is set, the request is POSTed (form-encoded) with a
// client assertion; otherwise an unauthenticated GET with the params as query
// string is used.
func FetchEntityStatementCtx(
	ctx context.Context, fetchEndpoint, subID, issID string, fe ...*FederationEntityMetadata,
) (*EntityStatement, error) {
	return getEntityStatementOrConfigurationCtx(
		ctx, subID, issID, func(ctx context.Context) (*EntityStatement, error) {
			var fePtr *FederationEntityMetadata
			if len(fe) > 0 {
				fePtr = fe[0]
			}
			return httpFetchEntityStatementCtx(ctx, fetchEndpoint, subID, fePtr)
		},
	)
}

// FetchEntityStatement fetches an EntityStatement from a fetch endpoint (see
// FetchEntityStatementCtx).
func FetchEntityStatement(fetchEndpoint, subID, issID string, fe ...*FederationEntityMetadata) (
	*EntityStatement, error,
) {
	return FetchEntityStatementCtx(context.Background(), fetchEndpoint, subID, issID, fe...)
}

func httpFetchEntityStatementCtx(
	ctx context.Context, fetchEndpoint, subID string, fe *FederationEntityMetadata,
) (*EntityStatement, error) {
	params := url.Values{}
	params.Add("sub", subID)
	var authMethods []string
	if fe != nil {
		authMethods = fe.FederationFetchEndpointAuthMethods
	}
	res, errRes, err := httpFederationEndpointRequestCtx(ctx, fetchEndpoint, params, authMethods, fe, nil)
	if err != nil {
		return nil, err
	}
	if errRes != nil {
		return nil, errRes.Err()
	}
	return ParseEntityStatement(res.Body())
}
