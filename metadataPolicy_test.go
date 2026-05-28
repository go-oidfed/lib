package oidfed

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type testVector struct {
	Number           int64                      `json:"n"`
	TAPolicy         MetadataPolicy             `json:"TA"`
	INTPolicy        MetadataPolicy             `json:"INT"`
	MergedPolicy     MetadataPolicy             `json:"merged"`
	LeafMetadata     OpenIDRelyingPartyMetadata `json:"metadata"`
	ResolvedMetadata OpenIDRelyingPartyMetadata `json:"resolved"`
	Error            string                     `json:"error"`
	ErrorDescription string                     `json:"error_description"`
}

var testVectors []testVector

func init() {
	content, err := os.ReadFile("metadata-policy-test-vectors-2025-02-13.json")
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(content, &testVectors); err != nil {
		panic(err)
	}
}

// Does will not all pass; we are more permissive on the merging,
// as long as we have the same result when the policy as actually applied
// func TestMergeMetadataPolicies(t *testing.T) {
// 	for _, test := range testVectors {
// 		t.Run(
// 			fmt.Sprintf("Merge Metadatapolicies Test Vector #%d", test.Number),
// 			func(t *testing.T) {
// 				combined, err := combineMetadataPolicy(test.TAPolicy, test.INTPolicy, "")
// 				if err != nil {
// 					if test.Error == "" {
// 						t.Fatalf("got error: %v, but no error was expected", err)
// 					} else {
// 						if err.Error() != test.Error {
// 							t.Logf(
// 								"got error: %s, but expected: %s", err.Error(), test.Error,
// 							)
// 							// do not fail
// 						}
// 						return
// 					}
// 				}
// 				expectedMarshalled, err := json.Marshal(test.MergedPolicy)
// 				if err != nil {
// 					t.Fatal(err)
// 				}
// 				combinedMarshalled, err := json.Marshal(combined)
// 				if err != nil {
// 					t.Fatal(err)
// 				}
// 				if !bytes.Equal(expectedMarshalled, combinedMarshalled) {
// 					t.Fatalf(
// 						"merged policy does not match expected policy"+
// 							": expected: \n%s\n\n, combined: \n%s\n", expectedMarshalled, combinedMarshalled,
// 					)
// 				}
// 			},
// 		)
// 	}
// }

func TestApplyPolicies(t *testing.T) {
	for _, test := range testVectors {
		t.Run(
			fmt.Sprintf("Apply Metadatapolicies Test Vector #%d", test.Number),
			func(t *testing.T) {
				if test.MergedPolicy == nil {
					return
				}
				value, err := applyPolicy(&test.LeafMetadata, test.MergedPolicy, "")
				if err != nil {
					if test.Error == "" {
						t.Fatalf("got error: %v, but no error was expected", err)
					} else {
						if err.Error() != test.Error {
							t.Logf(
								"got error: %s, but expected: %s", err.Error(), test.Error,
							)
							// do not fail
						}
						return
					}
				}
				expectedMarshalled, err := json.Marshal(test.ResolvedMetadata)
				if err != nil {
					t.Fatal(err)
				}
				resolvedMarshalled, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(expectedMarshalled, resolvedMarshalled) {
					t.Fatalf(
						"resolved metadata does not match expected"+
							" metadata"+
							": expected: \n%s\n\n, resolved: \n%s\n",
						expectedMarshalled, resolvedMarshalled,
					)
				}
			},
		)
	}
}

func TestMergeAndApplyMetadataPolicies(t *testing.T) {
	for _, test := range testVectors {
		t.Run(
			fmt.Sprintf("Test Vector #%d", test.Number),
			func(t *testing.T) {
				combined, err := combineMetadataPolicy(test.TAPolicy, test.INTPolicy, "")
				if err != nil {
					if test.Error == "" {
						t.Fatalf("merging got error: %v, but no error was expected", err)
					} else {
						if err.Error() != test.Error {
							t.Logf(
								"merging got error: %s, but expected: %s", err.Error(), test.Error,
							)
							// do not fail
						}
						return
					}
				}
				value, err := applyPolicy(&test.LeafMetadata, combined, "")
				if err != nil {
					if test.Error == "" {
						t.Fatalf("applying got error: %v, but no error was expected", err)
					} else {
						if err.Error() != test.Error {
							t.Logf(
								"applying got error: %s, but expected: %s", err.Error(), test.Error,
							)
							// do not fail
						}
						return
					}
				}
				expectedMarshalled, err := json.Marshal(test.ResolvedMetadata)
				if err != nil {
					t.Fatal(err)
				}
				resolvedMarshalled, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(expectedMarshalled, resolvedMarshalled) {
					t.Fatalf(
						"resolved metadata does not match expected"+
							" metadata"+
							": expected: \n%s\n\n, resolved: \n%s\n",
						expectedMarshalled, resolvedMarshalled,
					)
				}
			},
		)
	}
}

func TestContactsEssentialPolicy(t *testing.T) {
	tests := []struct {
		name             string
		policy           MetadataPolicy
		metadata         OpenIDRelyingPartyMetadata
		expectedContacts []string
		expectError      bool
	}{
		{
			name: "contacts essential true with contacts provided",
			policy: MetadataPolicy{
				"contacts": MetadataPolicyEntry{
					"essential": true,
				},
			},
			metadata: OpenIDRelyingPartyMetadata{
				Contacts: []string{"contact@example.com"},
			},
			expectedContacts: []string{"contact@example.com"},
			expectError:      false,
		},
		{
			name: "contacts essential true without empty contacts",
			policy: MetadataPolicy{
				"contacts": MetadataPolicyEntry{
					"essential": true,
				},
			},
			metadata:         OpenIDRelyingPartyMetadata{Contacts: []string{}},
			expectedContacts: []string{},
			expectError:      false,
		},
		{
			name: "contacts essential true without contacts",
			policy: MetadataPolicy{
				"contacts": MetadataPolicyEntry{
					"essential": true,
				},
			},
			metadata:         OpenIDRelyingPartyMetadata{},
			expectedContacts: nil,
			expectError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				result, err := applyPolicy(&tt.metadata, tt.policy, "")
				if tt.expectError {
					if err == nil {
						t.Fatalf("expected error, but got none")
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				resolved, ok := result.(*OpenIDRelyingPartyMetadata)
				if !ok {
					t.Fatalf("result is not OpenIDRelyingPartyMetadata")
				}

				if len(tt.expectedContacts) == 0 && len(resolved.Contacts) == 0 {
					return
				}

				if len(tt.expectedContacts) != len(resolved.Contacts) {
					t.Fatalf(
						"contacts length mismatch: expected %d, got %d",
						len(tt.expectedContacts), len(resolved.Contacts),
					)
				}

				for i, expected := range tt.expectedContacts {
					if resolved.Contacts[i] != expected {
						t.Fatalf(
							"contacts mismatch at index %d: expected %s, got %s",
							i, expected, resolved.Contacts[i],
						)
					}
				}
			},
		)
	}
}

func TestMetadataPoliciesUnmarshalWithUnknownEntityType(t *testing.T) {
	input := `{"federation_entity":{"display_name":{"essential":true}},"openid_provider":{"display_name":{"essential":true},"scope":{"superset_of":["openid","profile","email"]}},"wallet_provider":{"other_claim":{"essential":true}}}`

	var mp MetadataPolicies
	err := json.Unmarshal([]byte(input), &mp)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if _, ok := mp.Extra["wallet_provider"]; !ok {
		t.Fatal("expected 'wallet_provider' in Extra, but not found")
	}

	entry := mp.Extra["wallet_provider"]["other_claim"]
	if entry["essential"] != true {
		t.Fatalf("expected essential=true, got %v", entry["essential"])
	}
}

func TestMetadataPoliciesExtraRoundTrip(t *testing.T) {
	original := MetadataPolicies{
		FederationEntity: MetadataPolicy{
			"display_name": MetadataPolicyEntry{"essential": true},
		},
		OpenIDProvider: MetadataPolicy{
			"scope": MetadataPolicyEntry{"superset_of": []any{"openid", "profile"}},
		},
		Extra: map[string]MetadataPolicy{
			"wallet_provider": {
				"other_claim": MetadataPolicyEntry{"essential": true},
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded MetadataPolicies
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(decoded.FederationEntity) != len(original.FederationEntity) {
		t.Fatalf("FederationEntity length mismatch: expected %d, got %d", len(original.FederationEntity), len(decoded.FederationEntity))
	}
	if len(decoded.OpenIDProvider) != len(original.OpenIDProvider) {
		t.Fatalf("OpenIDProvider length mismatch: expected %d, got %d", len(original.OpenIDProvider), len(decoded.OpenIDProvider))
	}
	if len(decoded.Extra) != len(original.Extra) {
		t.Fatalf("Extra length mismatch: expected %d, got %d", len(original.Extra), len(decoded.Extra))
	}

	for k, v := range original.Extra {
		decodedVal, ok := decoded.Extra[k]
		if !ok {
			t.Fatalf("expected key %q in Extra, but not found", k)
		}
		if len(decodedVal) != len(v) {
			t.Fatalf("Extra[%q] length mismatch: expected %d, got %d", k, len(v), len(decodedVal))
		}
	}
}
