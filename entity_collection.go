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
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() { <-r.workerPool }() // release token
		task()
	}()
}

func (r *collectorResult) processAuthority(
	authority TrustAnchor,
	req apimodel.EntityCollectionRequest,
	collector *SimpleEntityCollector,
) {
	r.runWorker(
		func() {
			if collector.visitedEntities.Has(authority.EntityID) {
				internal.Logf("Already visited: %s -> skipping", authority.EntityID)
				return
			}
			collector.visitedEntities.Add(authority.EntityID)

			stmt, err := GetEntityConfiguration(authority.EntityID)
			if err != nil {
				internal.Logf("Could not get entity configuration: %s -> skipping", err.Error())
				return
			}

			if !hasValidFederationListEndpoint(stmt) {
				internal.Log("No FederationListEndpoint -> skipping")
				return
			}

			subordinates, err := fetchList(stmt.Metadata.FederationEntity.FederationListEndpoint)
			if err != nil {
				internal.Logf("Could not fetch subordinates: %s", err.Error())
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
				internal.Logf("Failed to get entity config for %s: %s", subordinateID, err.Error())
				return
			}

			if entityConfig.Metadata == nil {
				internal.Log("No metadata present -> skipping")
				return
			}

			et := entityConfig.Metadata.GuessEntityTypes()
			if r.shouldIncludeEntity(entityConfig, et, req) {
				entity := r.createCollectedEntity(subordinateID, et, entityConfig, req)
				r.entityChan <- entity
			}

			if hasValidFederationListEndpoint(entityConfig) {
				nested := collector.collect(req, NewTrustAnchorsFromEntityIDs(subordinateID)...)
				for _, nestedEntity := range nested {
					r.entityChan <- nestedEntity
				}
			}
		},
	)
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
	trustMarkInfo := entityConfig.TrustMarks.FindByID(trustMarkType)
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

	processUIClaims(entity, entityConfig, req)
	r.processTrustMarks(entity, entityConfig, req)

	return entity
}

func hasValidFederationListEndpoint(stmt *EntityStatement) bool {
	return stmt != nil &&
		stmt.Metadata != nil &&
		stmt.Metadata.FederationEntity != nil &&
		stmt.Metadata.FederationEntity.FederationListEndpoint != ""
}

func processUIClaims(
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
	}

	for _, claim := range uiInfoClaims {
		if len(req.UIClaims) == 0 || slices.Contains(req.UIClaims, claim) {
			entityConfig.Metadata.IterateMultilingualStringClaim(
				claim,
				func(entityType, langTag, value string) {
					// If language tags are specified in the request, only include those languages
					if shouldIncludeLanguage(langTag, req.LanguageTags) {
						_ = entity.setMultilingualUIInfoField(entityType, claim, langTag, value)
					}
				},
			)
		}
	}

	if len(req.UIClaims) == 0 || slices.Contains(req.UIClaims, "keywords") {
		entityConfig.Metadata.IterateStringSliceClaim(
			"keywords",
			func(entityType string, value []string) {
				_ = entity.setUIInfoField(entityType, "keywords", value)
			},
		)
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
