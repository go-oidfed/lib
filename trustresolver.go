package oidfed

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"

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
	Metadata    *Metadata              `json:"metadata,omitempty"`
	TrustMarks  TrustMarkInfos         `json:"trust_marks,omitempty"`
	TrustChain  JWSMessages            `json:"trust_chain,omitempty"`
	TrustAnchor string                 `json:"trust_anchor,omitempty"`
	Extra       map[string]interface{} `json:"-"`
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
	trustTree      trustTree
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
	}{
		StartingEntity: r.StartingEntity,
		TAs:            tas,
		Types:          r.Types,
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
	chains, set, err := r.cacheGetTrustChains()
	if err != nil {
		set = false
		internal.Log("TrustResolver: " + err.Error())
	}
	if set {
		internal.Log("TrustResolver: Obtained trust chains from cache")
		return chains
	}
	internal.Log("TrustResolver: Trust chains cache miss; resolving trust tree and verifying signatures")
	r.Resolve()
	r.VerifySignatures()
	return r.Chains()
}

// Resolve starts the trust chain resolution process, building an internal trust tree
func (r *TrustResolver) Resolve() {
	if found, err := r.cacheGetTrustTree(); err != nil {
		internal.Log("TrustResolver: " + err.Error())
	} else if found {
		internal.Log("TrustResolver: Obtained trust tree from cache")
		return
	}
	if r.StartingEntity == "" {
		internal.Log("TrustResolver: Resolve: no StartingEntity provided; aborting")
		return
	}
	starting, err := GetEntityConfiguration(r.StartingEntity)
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
	r.trustTree = trustTree{
		Entity:              starting,
		includedEntityTypes: strset.New(starting.Metadata.GuessEntityTypes()...),
		subordinateIDs:      strset.New(starting.Subject),
	}
	r.trustTree.resolve(r.TrustAnchors.EntityIDs())
	if err = r.cacheSetTrustTree(); err != nil {
		internal.Log("TrustResolver: " + err.Error())
	}
}

// VerifySignatures verifies the signatures of the internal trust tree
func (r *TrustResolver) VerifySignatures() {
	if !r.trustTree.verifySignatures(r.TrustAnchors) {
		internal.Log("TrustResolver: VerifySignatures: signature verification failed; clearing trust tree")
		r.trustTree = trustTree{}
	}
	if err := r.cacheSetTrustTree(); err != nil {
		internal.Log("TrustResolver: " + err.Error())
	}
	if r.trustTree.signaturesVerified {
		internal.Logf("TrustResolver: VerifySignatures: signature verification succeeded; valid authorities at root: %d", len(r.trustTree.Authorities))
	}
}

// Chains returns the TrustChains in the internal trust tree
func (r TrustResolver) Chains() (chains TrustChains) {
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
	if err = r.cacheSetTrustChains(chains); err != nil {
		internal.Log("TrustResolver: " + err.Error())
	}
	internal.Logf("TrustResolver: Chains: computed %d chain(s) and cached them", len(chains))
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
	ttl := unixtime.Until(r.trustTree.expiresAt)
	internal.Logf("TrustResolver: Caching trust chains with TTL %s (hash:%s)", ttl, hash)
	return cache.Set(
		cache.Key(cache.KeyTrustTreeChains, hash), chains,
		ttl,
	)
}

func (r *TrustResolver) cacheGetTrustTree() (
	set bool, err error,
) {
	hash, err := r.hash()
	if err != nil {
		return false, err
	}
	set, err = cache.Get(
		cache.Key(cache.KeyTrustTree, hash), &r.trustTree,
	)
	return
}
func (r TrustResolver) cacheSetTrustTree() error {
	hash, err := r.hash()
	if err != nil {
		return err
	}
	if err = cache.Delete(cache.Key(cache.KeyTrustTreeChains, hash)); err != nil {
		return err
	}
	ttl := unixtime.Until(r.trustTree.expiresAt)
	internal.Logf("TrustResolver: Caching trust tree with TTL %s (hash:%s)", ttl, hash)
	return cache.Set(
		cache.Key(cache.KeyTrustTree, hash), r.trustTree,
		ttl,
	)
}

// trustTree is a type for holding EntityStatements in a tree
type trustTree struct {
	Entity              *EntityStatement
	Subordinate         *EntityStatement
	Authorities         []trustTree
	signaturesVerified  bool
	expiresAt           unixtime.Unixtime
	depth               int
	includedEntityTypes *strset.Set
	subordinateIDs      *strset.Set
}

func (t *trustTree) resolve(anchors []string) {
	if t.Entity == nil {
		return
	}

	t.updateExpirationTime()

	// Early return if the entity is issued by a trust anchor
	if sliceutils.SliceContains(t.Entity.Issuer, anchors) {
		internal.Logf("TrustResolver: resolve: entity %s is issued by a trust anchor; early return", t.Entity.Issuer)
		return
	}

	t.resolveAuthorities(anchors)
}

func (t *trustTree) updateExpirationTime() {
	if t.expiresAt.IsZero() || t.expiresAt.Unix() == 0 || t.Entity.ExpiresAt.
		Before(t.expiresAt.Time) {
		t.expiresAt = t.Entity.ExpiresAt
	}
}

func (t *trustTree) resolveAuthorities(anchors []string) {
	if len(t.Entity.AuthorityHints) > 0 {
		t.Authorities = make([]trustTree, len(t.Entity.AuthorityHints))
	}

	internal.Logf("TrustResolver: resolveAuthorities: %d authority hint(s) for entity %s at depth %d", len(t.Entity.AuthorityHints), t.Entity.Issuer, t.depth)
	for i, authorityID := range t.Entity.AuthorityHints {
		internal.Logf("TrustResolver: resolveAuthorities: working on authority %s (hint %d/%d)", authorityID, i+1, len(t.Entity.AuthorityHints))
		if t.subordinateIDs.Has(authorityID) {
			internal.Logf(
				"TrustResolver: resolveAuthorities: skipping authority %s due to loop prevention", authorityID,
			)
			continue // Loop prevention
		}

		authority, err := t.resolveAuthority(authorityID, anchors)
		if err != nil {
			internal.Logf("TrustResolver: resolveAuthorities: failed resolving authority %s: %v", authorityID, err)
			continue
		}

		t.Authorities[i] = authority
		internal.Logf("TrustResolver: resolveAuthorities: successfully resolved authority %s; subtree depth %d with %d hint(s)", authorityID, authority.depth, len(authority.Entity.AuthorityHints))
	}
}

func (t *trustTree) resolveAuthority(authorityID string, anchors []string) (trustTree, error) {
	authorityStmt, err := GetEntityConfiguration(authorityID)
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
	internal.Logf("TrustResolver: resolveAuthority: authority statement valid for %s; fetch endpoint: %s", authorityID, authorityStmt.Metadata.FederationEntity.FederationFetchEndpoint)

	subordinateStmt, err := t.fetchAndValidateSubordinateStatement(authorityStmt, authorityID)
	if err != nil {
		internal.Logf(
			"TrustResolver: resolveAuthority: failed to fetch/validate subordinate stmt for %s->%s: %v", authorityID,
			t.Entity.Issuer,
			err,
		)
		return trustTree{}, err
	}
	internal.Logf("TrustResolver: resolveAuthority: subordinate statement valid for authority %s and subordinate %s", authorityID, t.Entity.Issuer)

	if !t.checkConstraints(subordinateStmt.Constraints) {
		internal.Logf(
			"TrustResolver: resolveAuthority: constraints check failed for authority %s and subordinate %s",
			authorityID,
			t.Entity.Issuer,
		)
		return trustTree{}, errors.New("constraints check failed")
	}
	internal.Logf("TrustResolver: resolveAuthority: constraints satisfied for authority %s and subordinate %s", authorityID, t.Entity.Issuer)

	t.updateExpirationTimeFromSubordinate(subordinateStmt)
	internal.Logf("TrustResolver: resolveAuthority: updated expiration to %v after subordinate stmt", t.expiresAt)

	subtree := t.createAuthorityTrustTree(authorityStmt, subordinateStmt, authorityID, anchors)
	internal.Logf("TrustResolver: resolveAuthority: created subtree for authority %s at depth %d (authorities: %d)", authorityID, subtree.depth, len(subtree.Authorities))
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
	subordinateStmt, err := FetchEntityStatement(
		authorityStmt.Metadata.FederationEntity.FederationFetchEndpoint, t.Entity.Issuer, authorityID,
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

func (t *trustTree) updateExpirationTimeFromSubordinate(subordinateStmt *EntityStatement) {
	if subordinateStmt.ExpiresAt.Before(t.expiresAt.Time) {
		t.expiresAt = subordinateStmt.ExpiresAt
	}
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
	}
	newTree.resolve(anchors)

	return newTree
}

func (t *trustTree) checkConstraints(constraints *ConstraintSpecification) bool {
	if constraints == nil {
		return true
	}
	internal.Logf("checking constraints %+v...", constraints)
	if constraints.MaxPathLength != nil && *constraints.MaxPathLength < t.depth {
		internal.Log("max path len constraint failed")
		return false
	}
	internal.Log("max path len constraint succeeded")
	if naming := constraints.NamingConstraints; naming != nil {
		internal.Logf("checking naming constraints %+v", naming)
		for _, id := range t.subordinateIDs.List() {
			if slices.ContainsFunc(
				naming.Excluded, func(e string) bool {
					return matchNamingConstraint(e, id)
				},
			) {
				internal.Log("naming constraint failed")
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
			internal.Log("naming constraint failed")
			return false
		}
	}
	internal.Log("naming constraint succeeded")
	if constraints.AllowedEntityTypes != nil {
		allowed := strset.New(append(constraints.AllowedEntityTypes, "federation_entity")...)
		forbidden := strset.Difference(t.includedEntityTypes, allowed)
		if !forbidden.IsEmpty() {
			internal.Log("entity type constraint failed")
			return false
		}
	}
	internal.Log("entity types constraint succeeded")
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
				jwks := ta.JWKS
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
	return getEntityStatementOrConfiguration(
		entityID, entityID, func() (*EntityStatement, error) {
			return httpGetEntityConfiguration(entityID)
		},
	)
}

func getEntityStatementOrConfiguration(
	subID, issID string, obtainerFnc func() (*EntityStatement, error),
) (*EntityStatement, error) {

	if stmt := entityStmtCacheGet(subID, issID); stmt != nil {
		internal.Log("Obtained entity statement from cache")
		go func() {
			remainingLifetime := time.Until(stmt.ExpiresAt.Time)
			totalLifetime := stmt.ExpiresAt.Sub(stmt.IssuedAt.Time)
			if remainingLifetime <= ResolverCacheGracePeriod && float64(remainingLifetime)/float64(totalLifetime) > ResolverCacheLifetimeElapsedGraceFactor {
				internal.Log("Within grace period, refreshing entity statement")
				_, err := obtainAndSetEntityStatementOrConfiguration(
					subID,
					issID, obtainerFnc,
				)
				if err != nil {
					internal.Log(err)
				}
			}
		}()
		return stmt, nil
	}
	return obtainAndSetEntityStatementOrConfiguration(subID, issID, obtainerFnc)
}

func obtainAndSetEntityStatementOrConfiguration(
	subID, issID string, obtainerFnc func() (*EntityStatement, error),
) (*EntityStatement, error) {
	stmt, err := obtainerFnc()
	if err != nil {
		internal.Log(err)
		return nil, err
	}
	internal.Log("Obtained entity statement from http")
	entityStmtCacheSet(subID, issID, stmt)
	return stmt, nil
}

func httpGetEntityConfiguration(
	entityID string,
) (*EntityStatement, error) {
	uri := strings.TrimSuffix(entityID, "/") + oidfedconst.FederationSuffix
	internal.Logf("Obtaining entity configuration from %+q", uri)
	res, errRes, err := http.Get(uri, nil, nil)
	if err != nil {
		return nil, err
	}
	if errRes != nil {
		return nil, errRes.Err()
	}
	return ParseEntityStatement(res.Body())
}

// FetchEntityStatement fetches an EntityStatement from a fetch endpoint
func FetchEntityStatement(fetchEndpoint, subID, issID string) (*EntityStatement, error) {
	return getEntityStatementOrConfiguration(
		subID, issID, func() (*EntityStatement, error) {
			return httpFetchEntityStatement(fetchEndpoint, subID)
		},
	)
}

func httpFetchEntityStatement(fetchEndpoint, subID string) (*EntityStatement, error) {
	uri := fetchEndpoint
	params := url.Values{}
	params.Add("sub", subID)
	res, errRes, err := http.Get(uri, params, nil)
	if err != nil {
		return nil, err
	}
	if errRes != nil {
		return nil, errRes.Err()
	}
	return ParseEntityStatement(res.Body())
}
