package oidfed

import (
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/zachmann/go-utils/sliceutils"

	"github.com/go-oidfed/lib/apimodel"
)

func TestSimpleOPCollector_CollectEntities(t *testing.T) {
	tests := []struct {
		name        string
		trustAnchor string
		expectedOPs []string
	}{
		{
			name:        "ta1",
			trustAnchor: ta1.EntityID,
			expectedOPs: []string{
				op1.EntityID,
				op2.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name:        "ta2",
			trustAnchor: ta2.EntityID,
			expectedOPs: []string{
				op1.EntityID,
				op2.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name:        "ia1",
			trustAnchor: ia1.EntityID,
			expectedOPs: []string{
				op1.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name:        "ia2",
			trustAnchor: ia2.EntityID,
			expectedOPs: []string{
				op1.EntityID,
				op2.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				res, _ := (&SimpleOPCollector{}).CollectEntities(
					apimodel.EntityCollectionRequest{TrustAnchor: test.trustAnchor},
				)
				if res == nil {
					t.Fatalf("ops is nil")
				}
				if len(res.FederationEntities) != len(test.expectedOPs) {
					t.Errorf("discovered OPs does not match expected OPs")
					t.Errorf("Expected: %+v", test.expectedOPs)
					t.Error("Discovered:")
					for _, op := range res.FederationEntities {
						t.Error(op.EntityID)
					}
					t.FailNow()
				}
				for _, op := range res.FederationEntities {
					if !sliceutils.SliceContains(op.EntityID, test.expectedOPs) {
						t.Errorf("discovered OPs does not match expected OPs")
						t.Errorf("discovered: %+v", op.EntityID)
						t.Errorf("expected: %+v", test.expectedOPs)
						t.FailNow()
					}
				}
			},
		)
	}
}

func TestSimpleRemoteEntityCollector_AggregatesRemotePagination(t *testing.T) {

	// Prepare a paginated mock endpoint
	endpoint := "https://mock.example/entities"
	all := []*CollectedEntity{
		{EntityID: "e1"},
		{EntityID: "e2"},
		{EntityID: "e3"},
		{EntityID: "e4"},
		{EntityID: "e5"},
	}

	// Paginated responder handling three pages
	httpmock.RegisterResponder(
		"GET", endpoint, func(req *http.Request) (*http.Response, error) {
			from := req.URL.Query().Get("from_entity_id")
			var res EntityCollectionResponse
			switch from {
			case "":
				res = EntityCollectionResponse{
					FederationEntities: []*CollectedEntity{
						all[0],
						all[1],
					},
					NextEntityID: all[2].EntityID,
				}
			case all[2].EntityID:
				res = EntityCollectionResponse{
					FederationEntities: []*CollectedEntity{
						all[2],
						all[3],
					},
					NextEntityID: all[4].EntityID,
				}
			case all[4].EntityID:
				res = EntityCollectionResponse{
					FederationEntities: []*CollectedEntity{all[4]},
				}
			default:
				res = EntityCollectionResponse{FederationEntities: nil}
			}
			return httpmock.NewJsonResponse(200, res)
		},
	)

	collector := SimpleRemoteEntityCollector{EntityCollectionEndpoint: endpoint}

	// Case 1: no limit set — remote still paginates, we aggregate all
	res, errRes := collector.CollectEntities(apimodel.EntityCollectionRequest{})
	if errRes != nil {
		t.Fatalf("unexpected error: %+v", errRes)
	}
	if res == nil {
		t.Fatalf("response is nil")
	}
	if len(res.FederationEntities) != len(all) {
		t.Fatalf("expected %d entities, got %d", len(all), len(res.FederationEntities))
	}
	if res.NextEntityID != "" {
		t.Fatalf("expected no pagination in final response, got next_entity_id=%q", res.NextEntityID)
	}
	for i, e := range res.FederationEntities {
		if e.EntityID != all[i].EntityID {
			t.Fatalf("entity order mismatch at %d: expected %q got %q", i, all[i].EntityID, e.EntityID)
		}
	}

	// Case 2: limit set — we forward it, but still aggregate all remote pages
	res2, errRes2 := collector.CollectEntities(apimodel.EntityCollectionRequest{Limit: 3})
	if errRes2 != nil {
		t.Fatalf("unexpected error (limit): %+v", errRes2)
	}
	if res2 == nil {
		t.Fatalf("response is nil (limit)")
	}
	if len(res2.FederationEntities) != len(all) {
		t.Fatalf("expected %d entities with limit, got %d", len(all), len(res2.FederationEntities))
	}
	if res2.NextEntityID != "" {
		t.Fatalf("expected no pagination in final response (limit), got next_entity_id=%q", res2.NextEntityID)
	}
}

func TestFilterableVerifiedChainsEntityCollector_CollectEntities(t *testing.T) {
	tests := []struct {
		name        string
		trustAnchor string
		filters     []EntityCollectionFilter
		expectedOPs []string
	}{
		{
			name:        "ta2",
			trustAnchor: ta2.EntityID,
			expectedOPs: []string{
				op1.EntityID,
				op2.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name: "ta2, automatic",
			filters: []EntityCollectionFilter{
				EntityCollectionFilterOPSupportsAutomaticRegistration([]string{ta2.EntityID}),
			},
			trustAnchor: ta2.EntityID,
			expectedOPs: []string{
				op1.EntityID,
				op2.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name: "ta2, automatic, scopes",
			filters: []EntityCollectionFilter{
				EntityCollectionFilterOPSupportsAutomaticRegistration([]string{ta2.EntityID}),
				EntityCollectionFilterOPSupportedScopesIncludes([]string{ta2.EntityID}, "openid", "profile", "email"),
			},
			trustAnchor: ta2.EntityID,
			expectedOPs: []string{
				op1.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name:        "ia1",
			trustAnchor: ia1.EntityID,
			expectedOPs: []string{
				op1.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name:        "ia1, automatic, scope:address",
			trustAnchor: ia1.EntityID,
			filters: []EntityCollectionFilter{
				EntityCollectionFilterOPSupportsAutomaticRegistration([]string{ia1.EntityID}),
				EntityCollectionFilterOPSupportedScopesIncludes([]string{ia1.EntityID}, "address"),
			},
			expectedOPs: []string{
				op1.EntityID,
			},
		},
		{
			name:        "ia1, automatic, scope:address, grant_type:rt",
			trustAnchor: ia1.EntityID,
			filters: []EntityCollectionFilter{
				EntityCollectionFilterOPSupportsAutomaticRegistration([]string{ia1.EntityID}),
				EntityCollectionFilterOPSupportedScopesIncludes([]string{ia1.EntityID}, "address"),
				EntityCollectionFilterOPSupportedGrantTypesIncludes([]string{ia1.EntityID}, "refresh_token"),
			},
			expectedOPs: nil,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				res, _ := FilterableVerifiedChainsEntityCollector{Filters: test.filters}.CollectEntities(
					apimodel.EntityCollectionRequest{
						TrustAnchor: test.trustAnchor,
						EntityTypes: []string{"openid_provider"},
					},
				)
				if res == nil {
					if test.expectedOPs == nil {
						return
					}
					t.Fatalf("ops is nil")
				}
				if len(res.FederationEntities) != len(test.expectedOPs) {
					t.Errorf("discovered OPs does not match expected OPs")
					t.Errorf("Expected: %+v", test.expectedOPs)
					t.Error("Discovered:")
					for _, op := range res.FederationEntities {
						t.Error(op.EntityID)
					}
					t.FailNow()
				}
				for _, op := range res.FederationEntities {
					if !sliceutils.SliceContains(op.EntityID, test.expectedOPs) {
						t.Errorf("discovered OPs does not match expected OPs")
						t.Errorf("discovered: %+v", op.EntityID)
						t.Errorf("expected: %+v", test.expectedOPs)
						t.FailNow()
					}
				}
			},
		)
	}
}
