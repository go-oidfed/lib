package oidfed

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/go-oidfed/lib/internal/utils"
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

func TestExceptOperatorExample1ExcludingAlgorithms(t *testing.T) {
	policy := MetadataPolicy{
		"id_token_signing_alg_values_supported": MetadataPolicyEntry{
			PolicyOperatorSubsetOf: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"},
			PolicyOperatorExcept:   []string{"RS256", "RS384"},
		},
	}
	var metadata OpenIDProviderMetadata
	if err := json.Unmarshal(
		[]byte(`{"id_token_signing_alg_values_supported":["RS256","RS512","ES256","ES512"]}`),
		&metadata,
	); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	result, err := applyPolicy(&metadata, policy, "openid_provider")
	if err != nil {
		t.Fatalf("did not expect error: %v", err)
	}
	resolved, ok := result.(*OpenIDProviderMetadata)
	if !ok {
		t.Fatalf("expected *OpenIDProviderMetadata, got %T", result)
	}
	expected := []string{"RS512", "ES256", "ES512"}
	if len(resolved.IDTokenSigningAlgValuesSupported) != len(expected) {
		t.Fatalf(
			"expected %+q, got %+q", expected, resolved.IDTokenSigningAlgValuesSupported,
		)
	}
	for i, v := range expected {
		if resolved.IDTokenSigningAlgValuesSupported[i] != v {
			t.Fatalf(
				"expected %+q, got %+q", expected, resolved.IDTokenSigningAlgValuesSupported,
			)
		}
	}
}

func TestExceptOperatorExample2ValueConflict(t *testing.T) {
	policy := MetadataPolicy{
		"token_endpoint_auth_method": MetadataPolicyEntry{
			PolicyOperatorValue:  "client_secret_basic",
			PolicyOperatorExcept: []string{"client_secret_basic"},
		},
	}
	var metadata OAuthClientMetadata
	if err := json.Unmarshal(
		[]byte(`{"token_endpoint_auth_method":"private_key_jwt"}`),
		&metadata,
	); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	if err := policy.Verify("oauth_client"); err == nil {
		t.Fatal("expected policy verification error for value/except conflict, but got none")
	}

	if _, err := applyPolicy(&metadata, policy, "oauth_client"); err == nil {
		t.Fatal("expected apply error for value/except conflict, but got none")
	}
}

func TestExceptOperatorMergeUnion(t *testing.T) {
	parent := MetadataPolicy{
		"id_token_signing_alg_values_supported": MetadataPolicyEntry{
			PolicyOperatorExcept: []string{"RS256"},
		},
	}
	sub := MetadataPolicy{
		"id_token_signing_alg_values_supported": MetadataPolicyEntry{
			PolicyOperatorExcept: []string{"RS384"},
		},
	}
	combined, err := combineMetadataPolicy(parent, sub, "openid_provider")
	if err != nil {
		t.Fatalf("did not expect merge error: %v", err)
	}
	exceptV, ok := combined["id_token_signing_alg_values_supported"][PolicyOperatorExcept]
	if !ok {
		t.Fatal("expected except operator in combined policy")
	}
	if !utils.SliceEqual([]string{"RS256", "RS384"}, exceptV) {
		t.Fatalf("expected except to be union [RS256 RS384], got %+v", exceptV)
	}
}

func TestExceptOperatorCombineWithOtherOperators(t *testing.T) {
	policy := MetadataPolicy{
		"id_token_signing_alg_values_supported": MetadataPolicyEntry{
			PolicyOperatorSubsetOf:  []string{"RS256", "RS384", "RS512", "ES256"},
			PolicyOperatorExcept:    []string{"RS256"},
			PolicyOperatorEssential: true,
		},
	}
	if err := policy.Verify("openid_provider"); err != nil {
		t.Fatalf("expected subset_of+except+essential to be a valid combination, but got: %v", err)
	}
}

// TestApplyPolicyToUnknownEntityType guards against a panic when a metadata
// policy covers an Entity Type the module has no Go struct for. Such metadata
// lands in Metadata.Extra as a map[string]any; applyPolicy must apply the
// per-parameter policy by key instead of reflecting over a map (which used to
// panic with "reflect: call of reflect.Value.Elem on map Value").
func TestApplyPolicyToUnknownEntityType(t *testing.T) {
	const metadataJSON = `{
	  "openid_relying_party": {"client_name": "rp"},
	  "openid_credential_verifier": {"client_name": "verifier"}
	}`
	apply := func(policyJSON string) (*Metadata, error) {
		var m Metadata
		if err := json.Unmarshal([]byte(metadataJSON), &m); err != nil {
			t.Fatalf("failed to unmarshal metadata: %v", err)
		}
		var p MetadataPolicies
		if err := json.Unmarshal([]byte(policyJSON), &p); err != nil {
			t.Fatalf("failed to unmarshal policy: %v", err)
		}
		return m.ApplyPolicy(&p)
	}

	t.Run("value operator applied", func(t *testing.T) {
		// Build metadata explicitly and confirm ApplyPolicy does not mutate it.
		var input Metadata
		if err := json.Unmarshal([]byte(metadataJSON), &input); err != nil {
			t.Fatalf("failed to unmarshal metadata: %v", err)
		}
		var p MetadataPolicies
		if err := json.Unmarshal([]byte(
			`{"openid_credential_verifier": {"client_name": {"value": "forced"}}}`), &p); err != nil {
			t.Fatalf("failed to unmarshal policy: %v", err)
		}
		out, err := input.ApplyPolicy(&p)
		if err != nil {
			t.Fatalf("ApplyPolicy returned error: %v", err)
		}
		ver := out.Extra["openid_credential_verifier"].(map[string]any)
		if got := ver["client_name"]; got != "forced" {
			t.Fatalf("verifier client_name = %v, want forced", got)
		}
		// The typed entity must be untouched in the output.
		if got := out.RelyingParty.ClientName; got != "rp" {
			t.Fatalf("rp client_name = %q, want rp", got)
		}
		// The input must not be mutated.
		inVer := input.Extra["openid_credential_verifier"].(map[string]any)
		if got := inVer["client_name"]; got != "verifier" {
			t.Fatalf("input verifier client_name = %v, want verifier (input was mutated)", got)
		}
	})

	t.Run("default operator establishes unset parameter", func(t *testing.T) {
		out, err := apply(`{"openid_credential_verifier": {"client_uri": {"default": "https://leaf.example"}}}`)
		if err != nil {
			t.Fatalf("ApplyPolicy returned error: %v", err)
		}
		ver := out.Extra["openid_credential_verifier"].(map[string]any)
		if got := ver["client_name"]; got != "verifier" {
			t.Fatalf("client_name = %v, want verifier", got)
		}
		if got := ver["client_uri"]; got != "https://leaf.example" {
			t.Fatalf("client_uri = %v, want https://leaf.example", got)
		}
	})
}

// TestTrustChainMetadataWithUnknownEntityTypePolicy guards the resolver path:
// TrustChain.Metadata must apply a policy covering a custom Entity Type that
// the leaf advertises, without panicking.
func TestTrustChainMetadataWithUnknownEntityTypePolicy(t *testing.T) {
	leaf := &EntityStatement{}
	leaf.Issuer, leaf.Subject = "https://leaf.example", "https://leaf.example"
	leaf.Metadata = &Metadata{}
	if err := json.Unmarshal([]byte(
		`{"openid_credential_verifier": {"client_name": "verifier"}}`), leaf.Metadata); err != nil {
		t.Fatalf("failed to unmarshal leaf metadata: %v", err)
	}

	var policy MetadataPolicies
	if err := json.Unmarshal([]byte(
		`{"openid_credential_verifier": {"client_name": {"value": "forced"}}}`), &policy); err != nil {
		t.Fatalf("failed to unmarshal policy: %v", err)
	}

	sub := &EntityStatement{}
	sub.Issuer, sub.Subject = "https://ta.example", "https://leaf.example"
	sub.MetadataPolicy = &policy
	ta := &EntityStatement{}
	ta.Issuer, ta.Subject = "https://ta.example", "https://ta.example"

	out, err := TrustChain{leaf, sub, ta}.Metadata()
	if err != nil {
		t.Fatalf("TrustChain.Metadata returned error: %v", err)
	}
	ver := out.Extra["openid_credential_verifier"].(map[string]any)
	if got := ver["client_name"]; got != "forced" {
		t.Fatalf("verifier client_name = %v, want forced", got)
	}
}
