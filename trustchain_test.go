package oidfed

import (
	"reflect"
	"testing"
	"time"

	"github.com/go-oidfed/lib/unixtime"
)

func TestMergeStructFields(t *testing.T) {
	type NestedStruct struct {
		FieldA int
		FieldB *string
	}

	type TestStruct struct {
		SimpleField int
		SliceField  []int
		MapField    map[string]int
		PtrField    *NestedStruct
		wasSet      map[string]bool
		Extra       map[string]interface{}
	}

	strValue := "test"
	tests := []struct {
		name     string
		target   TestStruct
		source   TestStruct
		expected TestStruct
	}{
		{
			name: "merge simple fields",
			target: TestStruct{
				SimpleField: 1,
				MapField:    map[string]int{"key1": 1},
			},
			source: TestStruct{
				SimpleField: 5,
			},
			expected: TestStruct{
				SimpleField: 5,
				MapField:    map[string]int{"key1": 1},
			},
		},
		{
			name: "merge slice fields",
			target: TestStruct{
				SliceField: []int{
					1,
					2,
				},
				MapField: map[string]int{"key1": 1},
			},
			source: TestStruct{
				SliceField: []int{
					2,
					3,
				},
			},
			expected: TestStruct{
				SliceField: []int{
					2,
					3,
				},
				MapField: map[string]int{"key1": 1},
			},
		},
		{
			name: "merge map fields",
			target: TestStruct{
				MapField: map[string]int{"key1": 1},
			},
			source: TestStruct{
				MapField: map[string]int{"key2": 2},
			},
			expected: TestStruct{
				MapField: map[string]int{
					"key1": 1,
					"key2": 2,
				},
			},
		},
		{
			name: "merge pointer fields",
			target: TestStruct{
				PtrField: &NestedStruct{
					FieldA: 10,
				},
			},
			source: TestStruct{
				PtrField: &NestedStruct{
					FieldA: 20,
					FieldB: &strValue,
				},
			},
			expected: TestStruct{
				PtrField: &NestedStruct{
					FieldA: 20,
					FieldB: &strValue,
				},
			},
		},
		{
			name: "merge with Extra field",
			target: TestStruct{
				Extra: map[string]interface{}{
					"key1": "value1",
					"key2": "value1",
				},
			},
			source: TestStruct{
				Extra: map[string]interface{}{
					"key2": "value2",
					"key3": "value3",
				},
			},
			expected: TestStruct{
				Extra: map[string]interface{}{
					"key1": "value1",
					"key2": "value2",
					"key3": "value3",
				},
			},
		},
		{
			name: "merge wasSet map",
			target: TestStruct{
				wasSet: map[string]bool{"SimpleField": true},
			},
			source: TestStruct{
				SimpleField: 15,
				wasSet:      map[string]bool{"SimpleField": false},
			},
			expected: TestStruct{
				SimpleField: 15,
				wasSet:      map[string]bool{"SimpleField": true},
			},
		},
	}

	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				targetVal := reflect.ValueOf(&test.target).Elem()
				sourceVal := reflect.ValueOf(&test.source).Elem()

				mergeStructFields(targetVal, sourceVal)

				if !reflect.DeepEqual(test.target, test.expected) {
					t.Errorf(
						"mergeStructFields() failed for %q: got %+v, want %+v", test.name, test.target, test.expected,
					)
				}
			},
		)
	}
}

func TestTrustChains_ExpiresAt(t *testing.T) {
	tests := []struct {
		name            string
		chain           TrustChain
		expiresExpected unixtime.Unixtime
	}{
		{
			name:            "emtpy",
			chain:           TrustChain{},
			expiresExpected: unixtime.Unixtime{},
		},
		{
			name: "single",
			chain: TrustChain{
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{
							Time: time.Unix(
								5, 0,
							),
						},
					},
				},
			},
			expiresExpected: unixtime.Unixtime{Time: time.Unix(5, 0)},
		},
		{
			name: "first min",
			chain: TrustChain{
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{
							Time: time.Unix(
								5, 0,
							),
						},
					},
				},
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{Time: time.Unix(10, 0)},
					},
				},
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{Time: time.Unix(100, 0)},
					},
				},
			},
			expiresExpected: unixtime.Unixtime{Time: time.Unix(5, 0)},
		},
		{
			name: "other min",
			chain: TrustChain{
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{Time: time.Unix(10, 0)},
					},
				},
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{
							Time: time.Unix(
								5, 0,
							),
						},
					},
				},
				&EntityStatement{
					EntityStatementPayload: EntityStatementPayload{
						ExpiresAt: unixtime.Unixtime{Time: time.Unix(100, 0)},
					},
				},
			},
			expiresExpected: unixtime.Unixtime{Time: time.Unix(5, 0)},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				expires := test.chain.ExpiresAt()
				if !expires.Equal(test.expiresExpected.Time) {
					t.Errorf("ExpiresAT() gives %v, but %v expected ", expires, test.expiresExpected)
				}
			},
		)
	}
}

func TestTrustChain_Metadata(t *testing.T) {
	chainRPIA2TA1Metadata := rp1.EntityStatementPayload().Metadata
	chainRPIA2TA1Metadata.RelyingParty.Contacts = append(chainRPIA2TA1Metadata.RelyingParty.Contacts, "ia@example.org")
	chainRPIA2TA2Metadata := chainRPIA2TA1Metadata
	chainRPIA2TA2Metadata.RelyingParty.Contacts = append(
		chainRPIA2TA2Metadata.RelyingParty.Contacts, "ta@foundation.example.org",
	)

	tests := []struct {
		name             string
		chain            TrustChain
		expectedMetadata *Metadata
		errExpected      bool
	}{
		{
			name:             "empty",
			chain:            TrustChain{},
			expectedMetadata: nil,
			errExpected:      true,
		},
		{
			name: "single",
			chain: TrustChain{
				&EntityStatement{EntityStatementPayload: rp1.EntityStatementPayload()},
			},
			expectedMetadata: rp1.EntityStatementPayload().Metadata,
			errExpected:      false,
		},
		{
			name:             "chain rp->ia1->ta1: nil policy",
			chain:            chainRPIA1TA1,
			expectedMetadata: rp1.EntityStatementPayload().Metadata,
			errExpected:      false,
		},
		{
			name:             "chain rp->ia2->ta1",
			chain:            chainRPIA2TA1,
			expectedMetadata: chainRPIA2TA1Metadata,
			errExpected:      false,
		},
		{
			name:             "chain rp->ia2->ta2",
			chain:            chainRPIA2TA2,
			expectedMetadata: chainRPIA2TA2Metadata,
			errExpected:      false,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				metadata, err := test.chain.Metadata()
				if err != nil {
					if test.errExpected {
						return
					}
					t.Error(err)
					return
				}
				if test.errExpected {
					t.Errorf("expected error, but no error returned")
					return
				}
				if !reflect.DeepEqual(metadata, test.expectedMetadata) {
					t.Errorf(
						"returned Metadata is not what we expected:\n\nReturned:\n%+v\n\nExpected:\n%+v\n\n",
						metadata, test.expectedMetadata,
					)
					return
				}
			},
		)
	}
}

func TestTrustChain_MetaDataPolicyCrit(t *testing.T) {
	chainRPIA2TA1Metadata := rp1.EntityStatementPayload().Metadata
	chainRPIA2TA1Metadata.RelyingParty.Contacts = append(chainRPIA2TA1Metadata.RelyingParty.Contacts, "ia@example.org")
	chainRPIA2TA2Metadata := chainRPIA2TA1Metadata
	chainRPIA2TA2Metadata.RelyingParty.Contacts = append(
		chainRPIA2TA2Metadata.RelyingParty.Contacts, "ta@foundation.example.org",
	)

	tests := []struct {
		name             string
		chain            TrustChain
		expectedMetadata *Metadata
		errExpected      bool
	}{
		{
			name:             "normal chain rp->ia2->ta2",
			chain:            chainRPIA2TA2,
			expectedMetadata: chainRPIA2TA2Metadata,
			errExpected:      false,
		},
		{
			name:             "non-crit chain rp->ia2->ta2WithRemove",
			chain:            chainRPIA2TA2WithRemove,
			expectedMetadata: chainRPIA2TA2Metadata,
			errExpected:      false,
		},
		{
			name:             "crit chain rp->ia2->ta2WithRemoveCrit",
			chain:            chainRPIA2TA2WithRemoveCrit,
			expectedMetadata: chainRPIA2TA2Metadata,
			errExpected:      true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				metadata, err := test.chain.Metadata()
				if err != nil {
					if test.errExpected {
						return
					}
					t.Error(err)
					return
				}
				if test.errExpected {
					t.Errorf("expected error, but no error returned")
					return
				}
				if !reflect.DeepEqual(metadata, test.expectedMetadata) {
					t.Errorf(
						"returned Metadata is not what we expected:\n\nReturned:\n%+v\n\nExpected:\n%+v\n\n",
						metadata, test.expectedMetadata,
					)
					return
				}
			},
		)
	}
}

func TestMergeMetadata_SourceNil_NoChange(t *testing.T) {
	target := &Metadata{
		OpenIDProvider: &OpenIDProviderMetadata{Issuer: "issuer-target"},
		Extra:          map[string]any{"k": "v"},
	}
	mergeMetadata(target, nil)
	if target.OpenIDProvider == nil || target.OpenIDProvider.Issuer != "issuer-target" {
		t.Fatalf("OpenIDProvider changed unexpectedly: %+v", target.OpenIDProvider)
	}
	if got := target.Extra["k"]; got != "v" {
		t.Fatalf("Extra changed unexpectedly: got %v", got)
	}
}

func TestMergeMetadata_TargetFieldNil_CopiesSource(t *testing.T) {
	source := &Metadata{
		OpenIDProvider: &OpenIDProviderMetadata{
			Issuer:                                "issuer-source",
			MTLSEndpointAliases:                   map[string]string{"a": "1"},
			Extra:                                 map[string]any{"sx": 1},
			RequestAuthenticationMethodsSupported: map[string][]string{"m1": {"a"}},
		},
		Extra: map[string]any{"top": "s"},
	}
	target := &Metadata{}
	mergeMetadata(target, source)
	if target.OpenIDProvider == nil || target.OpenIDProvider.Issuer != "issuer-source" {
		t.Fatalf("expected target OpenIDProvider copied from source, got %+v", target.OpenIDProvider)
	}
	if target.OpenIDProvider.MTLSEndpointAliases["a"] != "1" {
		t.Fatalf("expected MTLSEndpointAliases copied, got %+v", target.OpenIDProvider.MTLSEndpointAliases)
	}
	if target.OpenIDProvider.Extra["sx"].(int) != 1 {
		t.Fatalf("expected nested Extra copied, got %+v", target.OpenIDProvider.Extra)
	}
	if target.Extra["top"] != "s" {
		t.Fatalf("expected top-level Extra merged, got %+v", target.Extra)
	}
	if _, ok := target.OpenIDProvider.RequestAuthenticationMethodsSupported["m1"]; !ok {
		t.Fatalf(
			"expected m1 to be present in RequestAuthenticationMethodsSupported: %+v",
			target.OpenIDProvider.RequestAuthenticationMethodsSupported,
		)
	}
}

func TestMergeMetadata_BothNonNil_NestedMergeAndMapsAndExtra(t *testing.T) {
	target := &Metadata{
		OpenIDProvider: &OpenIDProviderMetadata{
			Issuer:              "issuer-target",
			Description:         "desc-target",
			MTLSEndpointAliases: map[string]string{"a": "1"},
			Extra: map[string]any{
				"ek1": "ev1",
				"ovr": "t",
			},
			RequestAuthenticationMethodsSupported: map[string][]string{"m1": {"a"}},
		},
		Extra: map[string]any{
			"x1": "t1",
			"o":  "t",
		},
	}
	source := &Metadata{
		OpenIDProvider: &OpenIDProviderMetadata{
			Issuer:      "issuer-source",
			Description: "", // empty should not override
			MTLSEndpointAliases: map[string]string{
				"a": "3",
				"b": "2",
			},
			Extra: map[string]any{
				"ovr": "s",
				"ns":  "v",
			},
			RequestAuthenticationMethodsSupported: map[string][]string{"m2": {"b"}},
		},
		Extra: map[string]any{
			"o":  "s",
			"x2": "s2",
		},
	}
	mergeMetadata(target, source)
	// Issuer should be overwritten
	if target.OpenIDProvider.Issuer != "issuer-source" {
		t.Fatalf("Issuer not overwritten, got %q", target.OpenIDProvider.Issuer)
	}
	// Description should remain from target because source is empty
	if target.OpenIDProvider.Description != "desc-target" {
		t.Fatalf("Description should not be overwritten by empty source, got %q", target.OpenIDProvider.Description)
	}
	// Map merge with override
	wantMTLS := map[string]string{
		"a": "3",
		"b": "2",
	}
	if !reflect.DeepEqual(target.OpenIDProvider.MTLSEndpointAliases, wantMTLS) {
		t.Fatalf(
			"MTLSEndpointAliases merge mismatch: got %+v, want %+v", target.OpenIDProvider.MTLSEndpointAliases, wantMTLS,
		)
	}
	// Nested Extra merged
	if target.OpenIDProvider.Extra["ek1"] != "ev1" || target.OpenIDProvider.Extra["ovr"] != "s" || target.OpenIDProvider.Extra["ns"] != "v" {
		t.Fatalf("nested Extra merge mismatch: %+v", target.OpenIDProvider.Extra)
	}
	// Top-level Extra merged
	if target.Extra["x1"] != "t1" || target.Extra["o"] != "s" || target.Extra["x2"] != "s2" {
		t.Fatalf("top-level Extra merge mismatch: %+v", target.Extra)
	}
	// Map[string][]string merge should add new keys and keep existing ones
	if _, ok := target.OpenIDProvider.RequestAuthenticationMethodsSupported["m1"]; !ok {
		t.Fatalf(
			"expected m1 to remain in RequestAuthenticationMethodsSupported: %+v",
			target.OpenIDProvider.RequestAuthenticationMethodsSupported,
		)
	}
	if _, ok := target.OpenIDProvider.RequestAuthenticationMethodsSupported["m2"]; !ok {
		t.Fatalf(
			"expected m2 to be added in RequestAuthenticationMethodsSupported: %+v",
			target.OpenIDProvider.RequestAuthenticationMethodsSupported,
		)
	}
}
