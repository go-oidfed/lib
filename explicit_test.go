package oidfed

import (
	"reflect"
	"testing"
)

func TestAdjustRPMetadataToOP_MultiValueAndScope(t *testing.T) {
	rp := &OpenIDRelyingPartyMetadata{
		ResponseTypes: []string{
			"code",
			"id_token",
		},
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
		},
		DefaultACRValues: []string{
			"loa2",
			"loa3",
		},
		AuthorizationDetailsTypes: []string{
			"payment",
			"openid_credential",
		},
		ClientRegistrationTypes: []string{
			"automatic",
			"explicit",
		},
		Scope: "openid profile email",
	}
	op := &OpenIDProviderMetadata{
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{"authorization_code"},
		ACRValuesSupported:     []string{"loa3"},
		AuthorizationDetailsTypesSupported: []string{
			"openid_credential",
			"other",
		},
		ClientRegistrationTypesSupported: []string{"automatic"},
		ScopesSupported: []string{
			"openid",
			"email",
		},
	}

	AdjustRPMetadataToOP(rp, op)

	if !reflect.DeepEqual(rp.ResponseTypes, []string{"code"}) {
		t.Fatalf("response_types filtered mismatch: %#v", rp.ResponseTypes)
	}
	if !reflect.DeepEqual(rp.GrantTypes, []string{"authorization_code"}) {
		t.Fatalf("grant_types filtered mismatch: %#v", rp.GrantTypes)
	}
	if !reflect.DeepEqual(rp.DefaultACRValues, []string{"loa3"}) {
		t.Fatalf("default_acr_values filtered mismatch: %#v", rp.DefaultACRValues)
	}
	if !reflect.DeepEqual(rp.AuthorizationDetailsTypes, []string{"openid_credential"}) {
		t.Fatalf("authorization_details_types filtered mismatch: %#v", rp.AuthorizationDetailsTypes)
	}
	if !reflect.DeepEqual(rp.ClientRegistrationTypes, []string{"automatic"}) {
		t.Fatalf("client_registration_types filtered mismatch: %#v", rp.ClientRegistrationTypes)
	}
	if got := rp.Scope; got != "openid email" {
		t.Fatalf("scope filtered mismatch: %q", got)
	}
}

func TestAdjustRPMetadataToOP_SingleValueDirectAndExtra(t *testing.T) {
	rp := &OpenIDRelyingPartyMetadata{
		SubjectType:                    "pairwise",
		IDTokenSignedResponseAlg:       "RS256",              // not supported; should fallback via Extra
		RequestObjectSigningAlg:        "RS256",              // not supported; should fallback via Extra
		TokenEndpointAuthMethod:        "client_secret_post", // not supported; should fallback via Extra
		IntrospectionSignedResponseAlg: "RS256",              // not supported and no Extra -> cleared
		Extra: map[string]any{
			"id_token_signing_alg_values_supported": []string{
				"ES512",
				"RS256",
			},
			"request_object_signing_alg_values_supported": []string{
				"RS256",
				"ES256",
			},
			"token_endpoint_auth_methods_supported": []string{
				"private_key_jwt",
				"client_secret_post",
			},
		},
	}
	op := &OpenIDProviderMetadata{
		SubjectTypesSupported: []string{
			"public",
			"pairwise",
		},
		IDTokenSigningAlgValuesSupported: []string{
			"ES256",
			"ES512",
		},
		RequestObjectSigningAlgValuesSupported: []string{"ES256"},
		TokenEndpointAuthMethodsSupported: []string{
			"private_key_jwt",
			"client_secret_basic",
		},
		IntrospectionSigningAlgValuesSupported: []string{"ES256"},
	}

	AdjustRPMetadataToOP(rp, op)

	if rp.SubjectType != "pairwise" {
		t.Fatalf("subject_type mismatch: %q", rp.SubjectType)
	}
	if rp.IDTokenSignedResponseAlg != "ES512" { // first common from Extra list
		t.Fatalf("id_token_signed_response_alg mismatch: %q", rp.IDTokenSignedResponseAlg)
	}
	if rp.RequestObjectSigningAlg != "ES256" {
		t.Fatalf("request_object_signing_alg mismatch: %q", rp.RequestObjectSigningAlg)
	}
	if rp.TokenEndpointAuthMethod != "private_key_jwt" {
		t.Fatalf("token_endpoint_auth_method mismatch: %q", rp.TokenEndpointAuthMethod)
	}
	if rp.IntrospectionSignedResponseAlg != "" { // unsupported and no Extra -> cleared
		t.Fatalf("introspection_signed_response_alg should be empty, got: %q", rp.IntrospectionSignedResponseAlg)
	}
}

func TestAdjustRPMetadataToOP_NoRestrictionsKeepValues(t *testing.T) {
	rp := &OpenIDRelyingPartyMetadata{
		ResponseTypes: []string{
			"code",
			"id_token",
		},
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
		},
		Scope:       "openid profile",
		SubjectType: "public",
	}
	op := &OpenIDProviderMetadata{
		// No supported lists -> should not constrain
	}

	AdjustRPMetadataToOP(rp, op)

	if !reflect.DeepEqual(
		rp.ResponseTypes, []string{
			"code",
			"id_token",
		},
	) {
		t.Fatalf("response_types should be unchanged: %#v", rp.ResponseTypes)
	}
	if !reflect.DeepEqual(
		rp.GrantTypes, []string{
			"authorization_code",
			"refresh_token",
		},
	) {
		t.Fatalf("grant_types should be unchanged: %#v", rp.GrantTypes)
	}
	if got := rp.Scope; got != "openid profile" {
		t.Fatalf("scope should be unchanged: %q", got)
	}
	if got := rp.SubjectType; got != "public" {
		t.Fatalf("subject_type should be unchanged: %q", got)
	}
}
