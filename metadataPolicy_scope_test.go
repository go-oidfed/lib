package oidfed

import (
	"encoding/json"
	"testing"
)

func TestApplyPoliciesToScope(t *testing.T) {
	tests := []struct {
		name     string
		input    OpenIDRelyingPartyMetadata
		policy   MetadataPolicy
		expected string
		wantErr  bool
	}{
		{
			name:  "subset_of filters scopes",
			input: OpenIDRelyingPartyMetadata{Scope: "openid profile email phone"},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorSubsetOf: []string{"openid", "profile"},
				},
			},
			expected: "openid profile",
			wantErr:  false,
		},
		{
			name:  "add operator adds new scopes",
			input: OpenIDRelyingPartyMetadata{Scope: "openid profile"},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorAdd: []string{"email", "offline_access"},
				},
			},
			expected: "openid profile email offline_access",
			wantErr:  false,
		},
		{
			name:  "value operator sets exact scopes",
			input: OpenIDRelyingPartyMetadata{Scope: "openid profile email"},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorValue: []string{"openid", "phone"},
				},
			},
			expected: "openid phone",
			wantErr:  false,
		},
		{
			name:  "default operator applies when not set",
			input: OpenIDRelyingPartyMetadata{Scope: ""},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorDefault: []string{"openid", "profile"},
				},
			},
			expected: "openid profile",
			wantErr:  false,
		},
		{
			name:  "default operator does not override existing value",
			input: OpenIDRelyingPartyMetadata{Scope: "openid"},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorDefault: []string{"openid", "profile"},
				},
			},
			expected: "openid",
			wantErr:  false,
		},
		{
			name:  "empty scope with subset_of",
			input: OpenIDRelyingPartyMetadata{Scope: ""},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorSubsetOf: []string{"openid", "profile"},
				},
			},
			expected: "",
			wantErr:  false,
		},
		{
			name:  "single scope",
			input: OpenIDRelyingPartyMetadata{Scope: "openid"},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorSubsetOf: []string{"openid", "profile"},
				},
			},
			expected: "openid",
			wantErr:  false,
		},
		{
			name:  "multiple spaces between scopes",
			input: OpenIDRelyingPartyMetadata{Scope: "openid   profile    email"},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorSubsetOf: []string{"openid", "email"},
				},
			},
			expected: "openid email",
			wantErr:  false,
		},
		{
			name:  "combined essential and subset_of",
			input: OpenIDRelyingPartyMetadata{Scope: "openid profile email"},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorEssential: true,
					PolicyOperatorSubsetOf:  []string{"openid", "profile"},
				},
			},
			expected: "openid profile",
			wantErr:  false,
		},
		{
			name:  "superset_of operator",
			input: OpenIDRelyingPartyMetadata{Scope: "openid profile email"},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorSupersetOf: []string{"openid", "profile"},
				},
			},
			expected: "openid profile email",
			wantErr:  false,
		},
		{
			name:  "no policy leaves scope unchanged",
			input: OpenIDRelyingPartyMetadata{Scope: "openid profile email"},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{},
			},
			expected: "openid profile email",
			wantErr:  false,
		},
		{
			name:     "nil policy leaves scope unchanged",
			input:    OpenIDRelyingPartyMetadata{Scope: "openid profile email"},
			policy:   MetadataPolicy{},
			expected: "openid profile email",
			wantErr:  false,
		},
		{
			name:  "one_of operator validation passes",
			input: OpenIDRelyingPartyMetadata{Scope: "openid"},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorOneOf: [][]string{{"openid"}, {"profile"}},
				},
			},
			expected: "openid",
			wantErr:  false,
		},
		{
			name:  "value operator with single scope",
			input: OpenIDRelyingPartyMetadata{Scope: "openid profile email"},
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorValue: []string{"openid"},
				},
			},
			expected: "openid",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := applyPolicy(&tt.input, tt.policy, "openid_relying_party")
			if (err != nil) != tt.wantErr {
				t.Fatalf("applyPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}

			rp, ok := result.(*OpenIDRelyingPartyMetadata)
			if !ok {
				t.Fatalf("result is not *OpenIDRelyingPartyMetadata")
			}

			if rp.Scope != tt.expected {
				t.Errorf("expected scope %q, got %q", tt.expected, rp.Scope)
			}
		})
	}
}

func TestApplyPoliciesToScopeWithMetadata(t *testing.T) {
	tests := []struct {
		name          string
		input         Metadata
		policy        *MetadataPolicies
		expectedScope string
	}{
		{
			name: "RP metadata with subset_of policy",
			input: Metadata{
				RelyingParty: &OpenIDRelyingPartyMetadata{
					Scope: "openid profile email phone",
				},
			},
			policy: &MetadataPolicies{
				RelyingParty: MetadataPolicy{
					"scope": MetadataPolicyEntry{
						PolicyOperatorSubsetOf: []string{"openid", "profile"},
					},
				},
			},
			expectedScope: "openid profile",
		},
		{
			name: "OAuthClient metadata with add policy",
			input: Metadata{
				OAuthClient: &OAuthClientMetadata{
					Scope: "openid profile",
				},
			},
			policy: &MetadataPolicies{
				OAuthClient: MetadataPolicy{
					"scope": MetadataPolicyEntry{
						PolicyOperatorAdd: []string{"email"},
					},
				},
			},
			expectedScope: "openid profile email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.input.ApplyPolicy(tt.policy)
			if err != nil {
				t.Fatalf("ApplyPolicy() error = %v", err)
			}

			var scope string
			if tt.input.RelyingParty != nil {
				scope = result.RelyingParty.Scope
			} else if tt.input.OAuthClient != nil {
				scope = result.OAuthClient.Scope
			}

			if scope != tt.expectedScope {
				t.Errorf("expected scope %q, got %q", tt.expectedScope, scope)
			}
		})
	}
}

func TestApplyPoliciesToScopeFromJSON(t *testing.T) {
	tests := []struct {
		name          string
		inputJSON     string
		policy        MetadataPolicy
		expectedScope string
		wantErr       bool
	}{
		{
			name: "subset_of filters scopes from JSON",
			inputJSON: `{
				"scope": "openid profile email phone"
			}`,
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorSubsetOf: []string{"openid", "profile"},
				},
			},
			expectedScope: "openid profile",
			wantErr:       false,
		},
		{
			name: "add operator adds new scopes from JSON",
			inputJSON: `{
				"scope": "openid profile"
			}`,
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorAdd: []string{"email", "offline_access"},
				},
			},
			expectedScope: "openid profile email offline_access",
			wantErr:       false,
		},
		{
			name: "value operator sets exact scopes from JSON",
			inputJSON: `{
				"scope": "openid profile email"
			}`,
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorValue: []string{"openid", "phone"},
				},
			},
			expectedScope: "openid phone",
			wantErr:       false,
		},
		{
			name: "combined operators from JSON",
			inputJSON: `{
				"scope": "openid profile email"
			}`,
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorSubsetOf: []string{"openid", "profile", "email", "phone"},
					PolicyOperatorAdd:      []string{"offline_access"},
				},
			},
			expectedScope: "openid profile email", // offline_access is filtered out by subset_of since it's applied after add
			wantErr:       false,
		},
		{
			name: "combined operators with allowed addition from JSON",
			inputJSON: `{
				"scope": "openid profile"
			}`,
			policy: MetadataPolicy{
				"scope": MetadataPolicyEntry{
					PolicyOperatorSubsetOf: []string{"openid", "profile", "email", "phone"},
					PolicyOperatorAdd:      []string{"email"},
				},
			},
			expectedScope: "openid profile email", // email is in subset_of list so it remains
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var input OpenIDRelyingPartyMetadata
			if err := json.Unmarshal([]byte(tt.inputJSON), &input); err != nil {
				t.Fatalf("failed to unmarshal input JSON: %v", err)
			}

			result, err := applyPolicy(&input, tt.policy, "openid_relying_party")
			if (err != nil) != tt.wantErr {
				t.Fatalf("applyPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}

			rp, ok := result.(*OpenIDRelyingPartyMetadata)
			if !ok {
				t.Fatalf("result is not *OpenIDRelyingPartyMetadata")
			}

			if rp.Scope != tt.expectedScope {
				t.Errorf("expected scope %q, got %q", tt.expectedScope, rp.Scope)
			}
		})
	}
}
