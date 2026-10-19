package oidfed

import (
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"

	"github.com/go-oidfed/lib/apimodel"
)

// TestSimpleEntityCollector_SubordinateCollectionEndpointFastPath verifies that
// when a subordinate publishes a federation_collection_endpoint, the collector
// uses it to enumerate the subtree instead of recursively descending the list
// endpoint, and enriches records whose requested info claims are missing.
func TestSimpleEntityCollector_SubordinateCollectionEndpointFastPath(t *testing.T) {
	leafA := newMockAuthority("https://leaf-a.example", EntityStatementPayload{})
	leafB := newMockAuthority("https://leaf-b.example", EntityStatementPayload{})
	sub := newMockAuthority("https://sub-collect.example", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-collect.example", EntityStatementPayload{})

	// The subordinate publishes a collection endpoint for its subtree.
	sub.data.Metadata.FederationEntity.FederationCollectionEndpoint = "https://sub-collect.example/collect"
	leafA.data.Metadata.FederationEntity.DisplayName = "Leaf A"
	leafB.data.Metadata.FederationEntity.DisplayName = "Leaf B"

	ta.RegisterSubordinate(sub)

	var collectCalls int
	httpmock.RegisterResponder(
		"GET", "https://sub-collect.example/collect",
		func(_ *http.Request) (*http.Response, error) {
			collectCalls++
			// The remote omits entity info claims; enrichment MUST fetch the leaf ECs.
			return httpmock.NewJsonResponse(
				200, EntityCollectionResponse{
					Entities: []*CollectedEntity{
						{EntityID: leafA.EntityID},
						{EntityID: leafB.EntityID},
					},
				},
			)
		},
	)
	// If the fast path is not taken, the collector would descend the list
	// endpoint. Fail loudly if that happens.
	httpmock.RegisterResponder(
		"GET", sub.ListEndpoint,
		httpmock.NewStringResponder(500, "list endpoint must not be called"),
	)

	res, errRes := (&SimpleEntityCollector{}).CollectEntities(
		apimodel.EntityCollectionRequest{
			TrustAnchor: ta.EntityID,
			InfoClaims:  []string{"display_name"},
		},
	)
	if errRes != nil {
		t.Fatalf("unexpected error: %+v", errRes)
	}
	if res == nil {
		t.Fatal("response is nil")
	}
	if collectCalls == 0 {
		t.Fatal("expected the subordinate collection endpoint to be called")
	}

	byID := make(map[string]*CollectedEntity)
	for _, e := range res.Entities {
		byID[e.EntityID] = e
	}
	// The leaves must have been enriched with their display names.
	if e, ok := byID[leafA.EntityID]; !ok {
		t.Fatalf("expected leaf A in results, got %+v", byID)
	} else if got := infoDisplayName(e, "federation_entity"); got != "Leaf A" {
		t.Fatalf("expected leaf A to be enriched with display_name %q, got %q", "Leaf A", got)
	}
	if e, ok := byID[leafB.EntityID]; !ok {
		t.Fatalf("expected leaf B in results, got %+v", byID)
	} else if got := infoDisplayName(e, "federation_entity"); got != "Leaf B" {
		t.Fatalf("expected leaf B to be enriched with display_name %q, got %q", "Leaf B", got)
	}
}

// TestSimpleEntityCollector_SubordinateCollectionEndpointFallback verifies that
// when the subordinate collection endpoint fails, the collector falls back to
// the classic recursive list traversal.
func TestSimpleEntityCollector_SubordinateCollectionEndpointFallback(t *testing.T) {
	leafA := newMockAuthority("https://leaf-c.example", EntityStatementPayload{})
	sub := newMockAuthority("https://sub-collect-fail.example", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-collect-fail.example", EntityStatementPayload{})

	sub.data.Metadata.FederationEntity.FederationCollectionEndpoint = "https://sub-collect-fail.example/collect"
	ta.RegisterSubordinate(sub)
	sub.RegisterSubordinate(leafA)

	// Collection endpoint returns an error -> must fall back to list traversal.
	httpmock.RegisterResponder(
		"GET", "https://sub-collect-fail.example/collect",
		httpmock.NewStringResponder(500, "boom"),
	)

	res, errRes := (&SimpleEntityCollector{}).CollectEntities(
		apimodel.EntityCollectionRequest{
			TrustAnchor: ta.EntityID,
		},
	)
	if errRes != nil {
		t.Fatalf("unexpected error: %+v", errRes)
	}
	if res == nil {
		t.Fatal("response is nil")
	}
	found := false
	for _, e := range res.Entities {
		if e.EntityID == leafA.EntityID {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected leaf to be discovered via fallback list traversal, got %+v", entityIDs(res.Entities))
	}
}

// TestSimpleEntityCollector_SubordinateCollectionDisabled verifies that the
// opt-out switch restores the classic recursive list traversal even when a
// subordinate publishes a collection endpoint.
func TestSimpleEntityCollector_SubordinateCollectionDisabled(t *testing.T) {
	leafA := newMockAuthority("https://leaf-d.example", EntityStatementPayload{})
	sub := newMockAuthority("https://sub-collect-off.example", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-collect-off.example", EntityStatementPayload{})

	sub.data.Metadata.FederationEntity.FederationCollectionEndpoint = "https://sub-collect-off.example/collect"
	ta.RegisterSubordinate(sub)
	sub.RegisterSubordinate(leafA)

	httpmock.RegisterResponder(
		"GET", "https://sub-collect-off.example/collect",
		httpmock.NewStringResponder(500, "collection endpoint must not be called"),
	)

	collector := &SimpleEntityCollector{DisableSubordinateCollectionEndpoints: true}
	res, errRes := collector.CollectEntities(
		apimodel.EntityCollectionRequest{
			TrustAnchor: ta.EntityID,
		},
	)
	if errRes != nil {
		t.Fatalf("unexpected error: %+v", errRes)
	}
	if res == nil {
		t.Fatal("response is nil")
	}
	found := false
	for _, e := range res.Entities {
		if e.EntityID == leafA.EntityID {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected leaf to be discovered via list traversal, got %+v", entityIDs(res.Entities))
	}
}

// TestHasValidFederationCollectionEndpoint verifies the metadata accessor.
func TestHasValidFederationCollectionEndpoint(t *testing.T) {
	if hasValidFederationCollectionEndpoint(nil) {
		t.Fatal("nil statement must not have a collection endpoint")
	}
	stmt := &EntityStatement{
		EntityStatementPayload: EntityStatementPayload{
			Metadata: &Metadata{
				FederationEntity: &FederationEntityMetadata{
					FederationCollectionEndpoint: "https://example/collect",
				},
			},
		},
	}
	if !hasValidFederationCollectionEndpoint(stmt) {
		t.Fatal("expected statement with collection endpoint to be detected")
	}
	stmt.Metadata.FederationEntity.FederationCollectionEndpoint = ""
	if hasValidFederationCollectionEndpoint(stmt) {
		t.Fatal("statement without collection endpoint must not be detected")
	}
}

func infoDisplayName(e *CollectedEntity, entityType string) string {
	if e == nil || e.EntityInfos == nil {
		return ""
	}
	if info, ok := e.EntityInfos[entityType]; ok {
		return info.DisplayName
	}
	return ""
}

func entityIDs(entities []*CollectedEntity) []string {
	ids := make([]string, 0, len(entities))
	for _, e := range entities {
		if e != nil {
			ids = append(ids, e.EntityID)
		}
	}
	return ids
}
