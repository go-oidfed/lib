package oidfed

import (
	"testing"

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
				ops := (&SimpleOPCollector{}).CollectEntities(
					apimodel.EntityCollectionRequest{TrustAnchor: test.trustAnchor},
				)
				if ops == nil {
					t.Fatalf("ops is nil")
				}
				if len(ops) != len(test.expectedOPs) {
					t.Errorf("discovered OPs does not match expected OPs")
					t.Errorf("Expected: %+v", test.expectedOPs)
					t.Error("Discovered:")
					for _, op := range ops {
						t.Error(op.EntityID)
					}
					t.FailNow()
				}
				for _, op := range ops {
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
				ops := FilterableVerifiedChainsEntityCollector{Filters: test.filters}.CollectEntities(
					apimodel.EntityCollectionRequest{
						TrustAnchor: test.trustAnchor,
						EntityTypes: []string{"openid_provider"},
					},
				)
				if ops == nil {
					if test.expectedOPs == nil {
						return
					}
					t.Fatalf("ops is nil")
				}
				if len(ops) != len(test.expectedOPs) {
					t.Errorf("discovered OPs does not match expected OPs")
					t.Errorf("Expected: %+v", test.expectedOPs)
					t.Error("Discovered:")
					for _, op := range ops {
						t.Error(op.EntityID)
					}
					t.FailNow()
				}
				for _, op := range ops {
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
