package oidfed

import (
	"slices"
	"sync"

	arrays "github.com/adam-hanna/arrayOperations"
	"golang.org/x/text/language"

	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/internal"
)

type collectorResult struct {
	entities   []*CollectedEntity
	seen       map[string]bool
	seenMu     sync.Mutex
	entityChan chan *CollectedEntity
	doneChan   chan struct{}
	workerPool chan struct{}
	wg         sync.WaitGroup
	ta         *EntityStatement
	taErr      error
	taOnce     sync.Once
}

func (r *collectorResult) collectEntities() {
	for e := range r.entityChan {
		r.seenMu.Lock()
		if !r.seen[e.EntityID] {
			r.seen[e.EntityID] = true
			r.entities = append(r.entities, e)
		}
		r.seenMu.Unlock()
	}
	r.doneChan <- struct{}{}
}

func (r *collectorResult) runWorker(task func()) {
	r.workerPool <- struct{}{} // acquire token
	r.wg.Go(
		func() {
			defer func() { <-r.workerPool }() // release token
			task()
		},
	)
}

func (r *collectorResult) processAuthority(
	authority *TrustAnchor,
	req apimodel.EntityCollectionRequest,
	collector *SimpleEntityCollector,
) {
	r.runWorker(
		func() {
			if collector.visitedEntities.Has(authority.EntityID) {
				internal.Logf("Discovery: Already visited: %s -> skipping", authority.EntityID)
				return
			}
			collector.visitedEntities.Add(authority.EntityID)

			stmt, err := GetEntityConfiguration(authority.EntityID)
			if err != nil {
				internal.Logf("Discovery: Could not get entity configuration: %s -> skipping", err.Error())
				return
			}

			if !hasValidFederationListEndpoint(stmt) {
				internal.Log("Discovery: No FederationListEndpoint -> skipping")
				return
			}

			subordinates, err := fetchList(
				stmt.Metadata.FederationEntity.FederationListEndpoint,
				stmt.Metadata.FederationEntity,
			)
			if err != nil {
				internal.Logf("Discovery: Could not fetch subordinates: %s", err.Error())
				return
			}

			for _, subordinateID := range subordinates {
				r.processSubordinate(subordinateID, req, collector)
			}
		},
	)
}

func (r *collectorResult) processSubordinate(
	subordinateID string,
	req apimodel.EntityCollectionRequest,
	collector *SimpleEntityCollector,
) {
	r.runWorker(
		func() {
			entityConfig, err := GetEntityConfiguration(subordinateID)
			if err != nil {
				internal.Logf("Discovery: Failed to get entity config for %s: %s", subordinateID, err.Error())
				return
			}

			if entityConfig.Metadata == nil {
				internal.Log("Discovery: No metadata present -> skipping")
				return
			}

			et := entityConfig.Metadata.GuessEntityTypes()
			if r.shouldIncludeEntity(entityConfig, et, req) {
				entity := r.createCollectedEntity(subordinateID, et, entityConfig, req)
				r.entityChan <- entity
			}

			// Fast path: if the subordinate publishes a federation_collection_endpoint,
			// delegate enumeration of its whole subtree to that endpoint instead of
			// recursively descending its federation_list_endpoint level by level.
			if !collector.DisableSubordinateCollectionEndpoints &&
				hasValidFederationCollectionEndpoint(entityConfig) {
				remote, ok := r.collectViaCollectionEndpoint(
					entityConfig.Metadata.FederationEntity.FederationCollectionEndpoint,
					subordinateID, req,
				)
				if ok {
					for _, nestedEntity := range remote {
						r.entityChan <- nestedEntity
					}
					// Subtree fully handled by the collection endpoint.
					return
				}
				// Fall through to the classic recursive list traversal below.
			}

			if hasValidFederationListEndpoint(entityConfig) {
				nested := collector.collect(
					req, func() *TrustAnchor {
						ta := &TrustAnchor{EntityID: subordinateID}
						ta.SetJWKS(entityConfig.JWKS)
						return ta
					}(),
				)
				for _, nestedEntity := range nested {
					r.entityChan <- nestedEntity
				}
			}
		},
	)
}

// collectViaCollectionEndpoint delegates enumeration of a subordinate's whole
// subtree to its published federation_collection_endpoint. The forwarded
// request is anchored at the subordinate itself so the remote collection scope
// matches the subtree. It aggregates all pages. On success it returns the
// (possibly enriched) entities and true; on failure or an empty result it
// returns (nil, false) so the caller can fall back to recursive list traversal.
func (r *collectorResult) collectViaCollectionEndpoint(
	endpoint, subordinateID string,
	req apimodel.EntityCollectionRequest,
) ([]*CollectedEntity, bool) {
	subReq := req
	subReq.TrustAnchor = subordinateID
	subReq.From = "" // aggregate all pages

	remote := SimpleRemoteEntityCollector{EntityCollectionEndpoint: endpoint}
	remoteRes, errRes := remote.CollectEntities(subReq)
	if errRes != nil {
		errDesc := ""
		if errRes.Error != nil {
			errDesc = errRes.Error.ErrorDescription
		}
		internal.Logf(
			"Entity Collection: delegated subordinate collection endpoint for %s failed: %s", subordinateID, errDesc,
		)
		return nil, false
	}
	if remoteRes == nil || len(remoteRes.Entities) == 0 {
		internal.Logf(
			"Entity Collection: delegated subordinate collection endpoint for %s returned no entities -> falling back",
			subordinateID,
		)
		return nil, false
	}

	// The remote response is informational and may omit claims we are expected
	// to return. Fetch the leaf entity configuration only when a requested claim
	// is missing from the record.
	var out []*CollectedEntity
	for _, e := range remoteRes.Entities {
		if e == nil || e.EntityID == "" {
			continue
		}
		if r.enrichmentNeeded(e, req) {
			r.enrichLeaf(e, req)
		}
		out = append(out, e)
	}
	return out, true
}

// enrichmentNeeded reports whether the remote collection record omits claims
// that our own collection path would have populated for the given request, so
// that the leaf entity configuration should be fetched to complete it. This
// keeps the fast-path result consistent with the classic recursive traversal's
// default output (entity_types + entity_infos, plus trust_marks when requested).
func (r *collectorResult) enrichmentNeeded(e *CollectedEntity, req apimodel.EntityCollectionRequest) bool {
	if len(e.EntityInfos) == 0 {
		if req.Query != "" || len(req.InfoClaims) > 0 {
			// Query matching and info-claim extraction need display metadata.
			return true
		}
		// entity_infos are part of the default output too: the underlying
		// processInfoClaims populates them when no info_claims were requested.
		return true
	}
	if len(e.EntityTypes) == 0 {
		// entity_types are reported by default.
		return true
	}
	if slices.Contains(req.EntityClaims, "trust_marks") && len(e.TrustMarks) == 0 {
		return true
	}
	return false
}

// enrichLeaf fetches an entity configuration for a single collected entity and
// fills in only those parts that were missing from the remote collection
// record: entity types, info claims, and trust marks are each enriched
// independently when absent. If every expected part is already present this is
// a no-op (assuming enrichmentNeeded reported a real gap).
func (r *collectorResult) enrichLeaf(e *CollectedEntity, req apimodel.EntityCollectionRequest) {
	ec, err := GetEntityConfiguration(e.EntityID)
	if err != nil || ec == nil || ec.Metadata == nil {
		internal.Logf("Discovery: could not fetch entity config to enrich %s: %v", e.EntityID, err)
		return
	}
	if len(e.EntityTypes) == 0 {
		e.EntityTypes = ec.Metadata.GuessEntityTypes()
	}
	if len(e.EntityInfos) == 0 {
		processInfoClaims(e, ec, req)
	}
	if slices.Contains(req.EntityClaims, "trust_marks") && len(e.TrustMarks) == 0 {
		r.processTrustMarks(e, ec, req)
	}
}

func (r *collectorResult) shouldIncludeEntity(
	entityConfig *EntityStatement,
	entityTypes []string,
	req apimodel.EntityCollectionRequest,
) bool {
	if req.EntityTypes != nil && len(arrays.Intersect(entityTypes, req.EntityTypes)) == 0 {
		return false
	}

	if req.Query != "" {
		if entityConfig != nil && entityConfig.Metadata != nil {
			multilingualDisplayNames := entityConfig.Metadata.GuessMultilingualDisplayNames()
			if !matchMultilingualDisplayName(req.Query, multilingualDisplayNames, MatchModeFuzzy) {
				return false
			}
		} else {
			// If no metadata available, exclude the entity
			return false
		}
	}

	for _, trustMarkType := range req.TrustMarkTypes {
		if !r.verifyTrustMark(entityConfig, trustMarkType, req.TrustAnchor) {
			return false
		}
	}

	return true
}

func (r *collectorResult) verifyTrustMark(
	entityConfig *EntityStatement,
	trustMarkType string,
	trustAnchor string,
) bool {
	trustMarkInfo := entityConfig.TrustMarks.FindByType(trustMarkType)
	if trustMarkInfo == nil {
		return false
	}

	r.taOnce.Do(
		func() {
			r.ta, r.taErr = GetEntityConfiguration(trustAnchor)
		},
	)

	if r.taErr != nil || trustMarkInfo.VerifyFederation(&r.ta.EntityStatementPayload) != nil {
		return false
	}

	return true
}

func (r *collectorResult) createCollectedEntity(
	entityID string,
	entityTypes []string,
	entityConfig *EntityStatement,
	req apimodel.EntityCollectionRequest,
) *CollectedEntity {
	entity := &CollectedEntity{EntityID: entityID}

	if len(req.EntityClaims) == 0 || slices.Contains(req.EntityClaims, "entity_types") {
		entity.EntityTypes = entityTypes
	}

	processInfoClaims(entity, entityConfig, req)
	r.processTrustMarks(entity, entityConfig, req)

	return entity
}

func hasValidFederationListEndpoint(stmt *EntityStatement) bool {
	return stmt != nil &&
		stmt.Metadata != nil &&
		stmt.Metadata.FederationEntity != nil &&
		stmt.Metadata.FederationEntity.FederationListEndpoint != ""
}

func hasValidFederationCollectionEndpoint(stmt *EntityStatement) bool {
	return stmt != nil &&
		stmt.Metadata != nil &&
		stmt.Metadata.FederationEntity != nil &&
		stmt.Metadata.FederationEntity.FederationCollectionEndpoint != ""
}

func processInfoClaims(
	entity *CollectedEntity,
	entityConfig *EntityStatement,
	req apimodel.EntityCollectionRequest,
) {
	uiInfoClaims := []string{
		"display_name",
		"description",
		"logo_uri",
		"policy_uri",
		"information_uri",
		"organization_name",
		"organization_uri",
	}
	sliceClaims := []string{
		"contacts",
		"keywords",
	}

	for _, claim := range uiInfoClaims {
		if len(req.InfoClaims) == 0 || slices.Contains(req.InfoClaims, claim) {
			entityConfig.Metadata.IterateMultilingualStringClaim(
				claim,
				func(entityType, langTag, value string) {
					// If language tags are specified in the request, only include those languages
					if shouldIncludeLanguage(langTag, req.LanguageTags) {
						_ = entity.setMultilingualEntityTypeInfoField(entityType, claim, langTag, value)
					}
				},
			)
		}
	}
	for _, claim := range sliceClaims {
		if len(req.InfoClaims) == 0 || slices.Contains(req.InfoClaims, claim) {
			entityConfig.Metadata.IterateStringSliceClaim(
				claim,
				func(entityType string, value []string) {
					_ = entity.setEntityTypeInfoField(entityType, claim, value)
				},
			)
		}
	}
}

// shouldIncludeLanguage determines if a language tag should be included based on the requested language tags.
// This function is used to filter multilingual UI claims based on the language preferences
// specified in the EntityCollectionRequest.
//
// The function follows these rules:
// 1. If no language tags are specified in the request, all languages are included
// 2. The default/untagged value (empty string) is always included
// 3. A language tag is included if it matches one of the requested language tags according to RFC4647
//
// This implementation uses the golang.org/x/text/language package to perform advanced language
// tag matching according to RFC4647. This means that broader language tags will match more
// specific ones (e.g., "en" matches "en-US", "en-GB", etc.).
//
// Parameters:
// - langTag: The language tag to check (empty string for default/untagged value)
// - requestedLangTags: The list of requested language tags from the EntityCollectionRequest
//
// Returns:
// - true if the language tag should be included, false otherwise
func shouldIncludeLanguage(langTag string, requestedLangTags []string) bool {
	// If no language tags are specified in the request, include all languages
	if len(requestedLangTags) == 0 {
		return true
	}

	// Empty language tag (default/untagged value) is always included
	if langTag == "" {
		return true
	}

	// Parse the language tag to check
	tag, err := language.Parse(langTag)
	if err != nil {
		// If the tag is invalid, fall back to exact matching
		return slices.Contains(requestedLangTags, langTag)
	}

	// Create a slice of language tags from the requested tags
	var supportedTags []language.Tag
	for _, reqTag := range requestedLangTags {
		parsed, err := language.Parse(reqTag)
		if err != nil {
			// Skip invalid tags
			continue
		}
		supportedTags = append(supportedTags, parsed)
	}

	// If there are no valid requested tags, include all languages
	if len(supportedTags) == 0 {
		return true
	}

	// Create a matcher with the requested language tags
	matcher := language.NewMatcher(supportedTags)

	// Check if the language tag matches any of the requested language tags
	// The matcher will handle the advanced matching according to RFC4647
	_, _, confidence := matcher.Match(tag)

	// Include the language if there's a match with at least low confidence
	// This ensures that broader tags match more specific ones (e.g., "en" matches "en-US")
	return confidence >= language.Low
}

func (r *collectorResult) processTrustMarks(
	entity *CollectedEntity,
	entityConfig *EntityStatement,
	req apimodel.EntityCollectionRequest,
) {
	if entity.TrustMarks != nil || !slices.Contains(
		req.EntityClaims, "trust_marks",
	) {
		return
	}
	r.taOnce.Do(
		func() {
			r.ta, r.taErr = GetEntityConfiguration(req.TrustAnchor)
		},
	)
	if r.taErr == nil {
		entity.TrustMarks = entityConfig.TrustMarks.VerifiedFederation(&r.ta.EntityStatementPayload)
	}
}
