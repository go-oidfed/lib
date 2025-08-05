package oidfed

import (
	"slices"
	"sync"

	arrays "github.com/adam-hanna/arrayOperations"

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
			displayNames := entityConfig.Metadata.GuessDisplayNames()

			if r.shouldIncludeEntity(entityConfig, et, displayNames, req) {
				entity := r.createCollectedEntity(subordinateID, et, entityConfig, displayNames, req)
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
	displayNames map[string]string,
	req apimodel.EntityCollectionRequest,
) bool {
	if req.EntityTypes != nil && len(arrays.Intersect(entityTypes, req.EntityTypes)) == 0 {
		return false
	}

	if req.Query != "" && !matchDisplayName(req.Query, displayNames, MatchModeFuzzy) {
		return false
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
	displayNames map[string]string,
	req apimodel.EntityCollectionRequest,
) *CollectedEntity {
	entity := &CollectedEntity{EntityID: entityID}

	if len(req.EntityClaims) == 0 || slices.Contains(req.EntityClaims, "entity_types") {
		entity.EntityTypes = entityTypes
	}

	processUIClaims(entity, entityConfig, req)
	processDisplayNames(entity, displayNames, req)
	r.processTrustMarks(entity, entityID, entityConfig, req)

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
		"description",
		"logo_uri",
		"policy_uri",
		"information_uri",
	}

	for _, claim := range uiInfoClaims {
		if len(req.UIClaims) == 0 || slices.Contains(req.UIClaims, claim) {
			entityConfig.Metadata.IterateStringClaim(
				claim,
				func(entityType, value string) {
					_ = entity.setUIInfoField(entityType, claim, value)
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

func processDisplayNames(
	entity *CollectedEntity,
	displayNames map[string]string,
	req apimodel.EntityCollectionRequest,
) {
	if len(req.UIClaims) == 0 || slices.Contains(req.UIClaims, "display_name") {
		for entityType, displayName := range displayNames {
			if displayName != "" {
				_ = entity.setUIInfoField(entityType, "display_name", displayName)
			}
		}
	}
}

func (r *collectorResult) processTrustMarks(
	entity *CollectedEntity,
	entityID string,
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
