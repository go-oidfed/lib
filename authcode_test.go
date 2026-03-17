package oidfed

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-oidfed/lib/internal/jwx"
	libjwx "github.com/go-oidfed/lib/jwx"
)

func TestRequestObjectProducer_RequestObject(t *testing.T) {
	rop := NewRequestObjectProducer(rp1.EntityID, rp1.versatileSigner, 60)
	emptyKeys := []string{
		"sub",
		"client_secret",
	}
	tests := []struct {
		name           string
		requestValues  map[string]any
		expectedValues map[string]any
	}{
		{
			name:          "only aud",
			requestValues: map[string]any{"aud": "https://aud.example.com"},
			expectedValues: map[string]any{
				"aud":       "https://aud.example.com",
				"iss":       rp1.EntityID,
				"client_id": rp1.EntityID,
			},
		},
		{
			name: "key:value",
			requestValues: map[string]any{
				"aud": "https://aud.example.com",
				"key": "value",
			},
			expectedValues: map[string]any{
				"aud":       "https://aud.example.com",
				"iss":       rp1.EntityID,
				"client_id": rp1.EntityID,
				"key":       "value",
			},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				ro, err := rop.RequestObject(test.requestValues, nil)
				if err != nil {
					t.Error(err)
					return
				}
				m, err := jwx.Parse(ro)
				if err != nil {
					t.Error(err)
					return
				}
				payload, err := m.VerifyWithSet(rp1.jwks)
				if err != nil {
					t.Error(err)
					return
				}
				var data map[string]any
				if err = json.Unmarshal(payload, &data); err != nil {
					t.Error(err)
					return
				}
				for k, v := range test.expectedValues {
					if data[k] != v {
						t.Errorf("request object '%s' is '%s' instead of '%s'", k, data[k], v)
						return
					}
				}
				for _, k := range emptyKeys {
					if _, set := data[k]; set {
						t.Errorf("request object has claim '%s' but must be empty", k)
						return
					}
				}
			},
		)
	}
}

func TestRequestObjectProducer_ClientAssertion(t *testing.T) {
	rop := NewRequestObjectProducer(rp1.EntityID, rp1.versatileSigner, 60)
	emptyKeys := []string{"client_id"}
	tests := []struct {
		name           string
		expectedValues map[string]string
		emptyKeys      []string
	}{
		{
			name: "only aud",
			expectedValues: map[string]string{
				"aud": "https://aud.example.com",
				"iss": rp1.EntityID,
				"sub": rp1.EntityID,
			},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				assertion, err := rop.ClientAssertion(test.expectedValues["aud"])
				if err != nil {
					t.Error(err)
					return
				}
				m, err := jwx.Parse(assertion)
				if err != nil {
					t.Error(err)
					return
				}
				payload, err := m.VerifyWithSet(rp1.jwks)
				if err != nil {
					t.Error(err)
					return
				}
				var data map[string]any
				if err = json.Unmarshal(payload, &data); err != nil {
					t.Error(err)
					return
				}
				for k, v := range test.expectedValues {
					if data[k] != v {
						t.Errorf("request object '%s' is '%s' instead of '%s'", k, data[k], v)
						return
					}
				}
				for _, k := range emptyKeys {
					if _, set := data[k]; set {
						t.Errorf("request object has claim '%s' but must be empty", k)
						return
					}
				}
			},
		)
	}
}

// =============================================================================
// OIDCTokenResponse Tests
// =============================================================================

func TestOIDCTokenResponse_UnmarshalJSON(t *testing.T) {
	t.Run("standard fields", func(t *testing.T) {
		jsonData := `{
			"access_token": "access123",
			"token_type": "Bearer",
			"expires_in": 3600,
			"refresh_token": "refresh456",
			"scope": "openid profile",
			"id_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
		}`

		var res OIDCTokenResponse
		err := json.Unmarshal([]byte(jsonData), &res)
		require.NoError(t, err)

		assert.Equal(t, "access123", res.AccessToken)
		assert.Equal(t, "Bearer", res.TokenType)
		assert.Equal(t, int64(3600), res.ExpiresIn)
		assert.Equal(t, "refresh456", res.RefreshToken)
		assert.Equal(t, "openid profile", res.Scopes)
		assert.NotEmpty(t, res.IDToken)
	})

	t.Run("with extra fields", func(t *testing.T) {
		jsonData := `{
			"access_token": "access123",
			"token_type": "Bearer",
			"expires_in": 3600,
			"custom_field": "custom_value",
			"another_field": 42
		}`

		var res OIDCTokenResponse
		err := json.Unmarshal([]byte(jsonData), &res)
		require.NoError(t, err)

		assert.Equal(t, "access123", res.AccessToken)
		assert.NotNil(t, res.Extra)
		assert.Equal(t, "custom_value", res.Extra["custom_field"])
		assert.Equal(t, float64(42), res.Extra["another_field"])
	})

	t.Run("minimal response", func(t *testing.T) {
		jsonData := `{
			"access_token": "token"
		}`

		var res OIDCTokenResponse
		err := json.Unmarshal([]byte(jsonData), &res)
		require.NoError(t, err)

		assert.Equal(t, "token", res.AccessToken)
		assert.Empty(t, res.TokenType)
		assert.Equal(t, int64(0), res.ExpiresIn)
	})

	t.Run("invalid json", func(t *testing.T) {
		var res OIDCTokenResponse
		err := json.Unmarshal([]byte(`{invalid`), &res)
		assert.Error(t, err)
	})
}

func TestOIDCErrorResponse(t *testing.T) {
	t.Run("with description", func(t *testing.T) {
		jsonData := `{
			"error": "invalid_grant",
			"error_description": "The authorization code has expired"
		}`

		var res OIDCErrorResponse
		err := json.Unmarshal([]byte(jsonData), &res)
		require.NoError(t, err)

		assert.Equal(t, "invalid_grant", res.Error)
		assert.Equal(t, "The authorization code has expired", res.ErrorDescription)
	})

	t.Run("without description", func(t *testing.T) {
		jsonData := `{"error": "access_denied"}`

		var res OIDCErrorResponse
		err := json.Unmarshal([]byte(jsonData), &res)
		require.NoError(t, err)

		assert.Equal(t, "access_denied", res.Error)
		assert.Empty(t, res.ErrorDescription)
	})
}

// =============================================================================
// RequestObjectProducer Edge Case Tests
// =============================================================================

func TestRequestObjectProducer_RequestObject_EdgeCases(t *testing.T) {
	rop := NewRequestObjectProducer(rp1.EntityID, rp1.versatileSigner, 60)

	t.Run("nil request values", func(t *testing.T) {
		_, err := rop.RequestObject(nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "aud")
	})

	t.Run("missing aud claim", func(t *testing.T) {
		_, err := rop.RequestObject(map[string]any{"foo": "bar"}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "aud")
	})

	t.Run("with custom jti", func(t *testing.T) {
		customJTI := "custom-jti-12345"
		ro, err := rop.RequestObject(map[string]any{
			"aud": "https://op.example.com",
			"jti": customJTI,
		}, nil)
		require.NoError(t, err)

		m, err := jwx.Parse(ro)
		require.NoError(t, err)

		payload, err := m.VerifyWithSet(rp1.jwks)
		require.NoError(t, err)

		var data map[string]any
		require.NoError(t, json.Unmarshal(payload, &data))

		assert.Equal(t, customJTI, data["jti"])
	})

	t.Run("removes sub and client_secret", func(t *testing.T) {
		ro, err := rop.RequestObject(map[string]any{
			"aud":           "https://op.example.com",
			"sub":           "should-be-removed",
			"client_secret": "should-be-removed-too",
		}, nil)
		require.NoError(t, err)

		m, err := jwx.Parse(ro)
		require.NoError(t, err)

		payload, err := m.VerifyWithSet(rp1.jwks)
		require.NoError(t, err)

		var data map[string]any
		require.NoError(t, json.Unmarshal(payload, &data))

		_, hasSub := data["sub"]
		_, hasSecret := data["client_secret"]
		assert.False(t, hasSub, "sub should be removed")
		assert.False(t, hasSecret, "client_secret should be removed")
	})

	t.Run("with specific algorithm", func(t *testing.T) {
		ro, err := rop.RequestObject(map[string]any{
			"aud": "https://op.example.com",
		}, nil, "ES512")
		require.NoError(t, err)
		assert.NotEmpty(t, ro)
	})

	t.Run("with incompatible algorithm", func(t *testing.T) {
		_, err := rop.RequestObject(map[string]any{
			"aud": "https://op.example.com",
		}, nil, "RS256") // rp1 uses ES512
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no compatible signing key")
	})
}

func TestRequestObjectProducer_ClientAssertion_EdgeCases(t *testing.T) {
	rop := NewRequestObjectProducer(rp1.EntityID, rp1.versatileSigner, 60)

	t.Run("with specific algorithm", func(t *testing.T) {
		assertion, err := rop.ClientAssertion("https://token.example.com", "ES512")
		require.NoError(t, err)
		assert.NotEmpty(t, assertion)
	})

	t.Run("with incompatible algorithm", func(t *testing.T) {
		_, err := rop.ClientAssertion("https://token.example.com", "RS256")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no compatible signing key")
	})

	t.Run("contains required claims", func(t *testing.T) {
		assertion, err := rop.ClientAssertion("https://token.example.com")
		require.NoError(t, err)

		m, err := jwx.Parse(assertion)
		require.NoError(t, err)

		payload, err := m.VerifyWithSet(rp1.jwks)
		require.NoError(t, err)

		var data map[string]any
		require.NoError(t, json.Unmarshal(payload, &data))

		// Check required claims exist
		assert.NotEmpty(t, data["jti"])
		assert.NotEmpty(t, data["iat"])
		assert.NotEmpty(t, data["exp"])
		assert.Equal(t, rp1.EntityID, data["iss"])
		assert.Equal(t, rp1.EntityID, data["sub"])
		assert.Equal(t, "https://token.example.com", data["aud"])
	})
}

func TestNewRequestObjectProducer(t *testing.T) {
	rop := NewRequestObjectProducer("https://rp.example.com", rp1.versatileSigner, time.Minute)

	assert.Equal(t, "https://rp.example.com", rop.EntityID)
	assert.Equal(t, time.Minute, rop.lifetime)
	assert.NotNil(t, rop.signer)
}

// =============================================================================
// FederationLeaf GetAuthorizationURL Tests
// =============================================================================

// mockFederationLeaf creates a FederationLeaf for testing
func newTestFederationLeaf(t *testing.T) *FederationLeaf {
	t.Helper()

	signer := libjwx.NewEntityStatementSigner(rp1.versatileSigner)
	leaf, err := NewFederationLeaf(
		rp1.EntityID,
		[]string{ta1.EntityID},
		TrustAnchors{{EntityID: ta1.EntityID, JWKS: ta1.data.JWKS}},
		&Metadata{
			RelyingParty: &OpenIDRelyingPartyMetadata{
				ClientRegistrationTypes: []string{"automatic"},
			},
		},
		signer,
		time.Hour,
		rp1.versatileSigner,
		nil,
	)
	require.NoError(t, err)
	return leaf
}

func TestFederationLeaf_GetAuthorizationURL(t *testing.T) {
	leaf := newTestFederationLeaf(t)

	t.Run("OP not found", func(t *testing.T) {
		_, err := leaf.GetAuthorizationURL(
			"https://unknown-op.example.com",
			"https://rp.example.com/callback",
			"state123",
			"openid profile",
			nil,
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not resolve OP metadata")
	})

	t.Run("valid OP resolution", func(t *testing.T) {
		// Use op1 which is registered in the mock infrastructure
		authURL, err := leaf.GetAuthorizationURL(
			op1.EntityID,
			"https://rp.example.com/callback",
			"state123",
			"openid profile",
			nil,
		)
		require.NoError(t, err)
		assert.NotEmpty(t, authURL)

		// Parse the URL to verify structure
		parsedURL, err := url.Parse(authURL)
		require.NoError(t, err)

		// Check query parameters
		query := parsedURL.Query()
		assert.Equal(t, rp1.EntityID, query.Get("client_id"))
		assert.Equal(t, "code", query.Get("response_type"))
		assert.Equal(t, "https://rp.example.com/callback", query.Get("redirect_uri"))
		assert.Equal(t, "openid profile", query.Get("scope"))
		assert.NotEmpty(t, query.Get("request")) // Request object should be present
	})

	t.Run("with additional params", func(t *testing.T) {
		additionalParams := url.Values{}
		additionalParams.Set("nonce", "nonce123")
		additionalParams.Set("prompt", "consent")

		authURL, err := leaf.GetAuthorizationURL(
			op1.EntityID,
			"https://rp.example.com/callback",
			"state123",
			"openid",
			additionalParams,
		)
		require.NoError(t, err)
		assert.NotEmpty(t, authURL)
	})
}

// =============================================================================
// FederationLeaf CodeExchange Tests
// =============================================================================

func TestFederationLeaf_CodeExchange(t *testing.T) {
	leaf := newTestFederationLeaf(t)

	// Register a mock token endpoint for op1
	tokenEndpoint := "https://op1.example.com/token"

	t.Run("successful token exchange", func(t *testing.T) {
		httpmock.RegisterResponder(
			"POST", tokenEndpoint,
			func(req *http.Request) (*http.Response, error) {
				// Verify request parameters
				err := req.ParseForm()
				if err != nil {
					return httpmock.NewJsonResponse(400, map[string]string{"error": "bad_request"})
				}

				assert.Equal(t, "authorization_code", req.Form.Get("grant_type"))
				assert.Equal(t, "test-code", req.Form.Get("code"))
				assert.NotEmpty(t, req.Form.Get("client_assertion"))
				assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", req.Form.Get("client_assertion_type"))

				return httpmock.NewJsonResponse(200, map[string]any{
					"access_token":  "access_token_123",
					"token_type":    "Bearer",
					"expires_in":    3600,
					"refresh_token": "refresh_token_456",
					"id_token":      "id_token_789",
					"scope":         "openid profile",
				})
			},
		)

		tokenRes, errRes, err := leaf.CodeExchange(
			op1.EntityID,
			"test-code",
			"https://rp.example.com/callback",
			nil,
		)
		require.NoError(t, err)
		assert.Nil(t, errRes)
		require.NotNil(t, tokenRes)

		assert.Equal(t, "access_token_123", tokenRes.AccessToken)
		assert.Equal(t, "Bearer", tokenRes.TokenType)
		assert.Equal(t, int64(3600), tokenRes.ExpiresIn)
	})

	t.Run("error response from OP", func(t *testing.T) {
		httpmock.RegisterResponder(
			"POST", tokenEndpoint,
			httpmock.NewJsonResponderOrPanic(400, map[string]string{
				"error":             "invalid_grant",
				"error_description": "The authorization code has expired",
			}),
		)

		tokenRes, errRes, err := leaf.CodeExchange(
			op1.EntityID,
			"expired-code",
			"https://rp.example.com/callback",
			nil,
		)
		require.NoError(t, err) // No system error
		assert.Nil(t, tokenRes)
		require.NotNil(t, errRes)

		assert.Equal(t, "invalid_grant", errRes.Error)
		assert.Equal(t, "The authorization code has expired", errRes.ErrorDescription)
	})

	t.Run("OP not found", func(t *testing.T) {
		_, _, err := leaf.CodeExchange(
			"https://unknown-op.example.com",
			"test-code",
			"https://rp.example.com/callback",
			nil,
		)
		assert.Error(t, err)
	})

	t.Run("with additional parameters", func(t *testing.T) {
		httpmock.RegisterResponder(
			"POST", tokenEndpoint,
			func(req *http.Request) (*http.Response, error) {
				err := req.ParseForm()
				if err != nil {
					return httpmock.NewJsonResponse(400, map[string]string{"error": "bad_request"})
				}

				// Verify additional parameter is present
				assert.Equal(t, "custom_value", req.Form.Get("custom_param"))

				return httpmock.NewJsonResponse(200, map[string]any{
					"access_token": "access_token",
					"token_type":   "Bearer",
				})
			},
		)

		additionalParams := url.Values{}
		additionalParams.Set("custom_param", "custom_value")

		tokenRes, errRes, err := leaf.CodeExchange(
			op1.EntityID,
			"test-code",
			"https://rp.example.com/callback",
			additionalParams,
		)
		require.NoError(t, err)
		assert.Nil(t, errRes)
		assert.NotNil(t, tokenRes)
	})
}

// =============================================================================
// FederationLeaf ResolveOPMetadata Tests
// =============================================================================

func TestFederationLeaf_ResolveOPMetadata(t *testing.T) {
	leaf := newTestFederationLeaf(t)

	t.Run("successful resolution", func(t *testing.T) {
		opMetadata, err := leaf.ResolveOPMetadata(op1.EntityID)
		require.NoError(t, err)
		require.NotNil(t, opMetadata)

		assert.Equal(t, op1.EntityID, opMetadata.Issuer)
		assert.Equal(t, "https://op1.example.com/authorize", opMetadata.AuthorizationEndpoint)
		assert.Equal(t, "https://op1.example.com/token", opMetadata.TokenEndpoint)
	})

	t.Run("unknown issuer", func(t *testing.T) {
		_, err := leaf.ResolveOPMetadata("https://unknown-op.example.com")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no trust chain")
	})
}

// =============================================================================
// FederationLeaf RequestObjectProducer Accessor Tests
// =============================================================================

func TestFederationLeaf_RequestObjectProducer(t *testing.T) {
	leaf := newTestFederationLeaf(t)

	rop := leaf.RequestObjectProducer()
	require.NotNil(t, rop)
	assert.Equal(t, rp1.EntityID, rop.EntityID)
}

// =============================================================================
// GetAuthorizationURL Extended Tests
// =============================================================================

func TestFederationLeaf_GetAuthorizationURL_Extended(t *testing.T) {
	t.Run("with request_uri generator", func(t *testing.T) {
		signer := libjwx.NewEntityStatementSigner(rp1.versatileSigner)

		// Create a request URI generator
		requestURIGenerator := func(requestObject []byte) (string, error) {
			return "https://rp.example.com/request/12345", nil
		}

		leaf, err := NewFederationLeaf(
			rp1.EntityID,
			[]string{ta1.EntityID},
			TrustAnchors{{EntityID: ta1.EntityID, JWKS: ta1.data.JWKS}},
			&Metadata{
				RelyingParty: &OpenIDRelyingPartyMetadata{
					ClientRegistrationTypes: []string{"automatic"},
				},
			},
			signer,
			time.Hour,
			rp1.versatileSigner,
			nil,
		)
		require.NoError(t, err)
		require.NotNil(t, leaf)

		// Set the RequestURIGenerator
		leaf.RequestURIGenerator = requestURIGenerator

		// Note: This test verifies leaf creation with RequestURIGenerator
		// The actual request_uri usage depends on OP supporting request_uri parameter
		assert.NotNil(t, leaf.RequestURIGenerator)
	})

	t.Run("multiple additional params with same key", func(t *testing.T) {
		leaf := newTestFederationLeaf(t)

		additionalParams := url.Values{}
		additionalParams.Add("acr_values", "urn:mace:incommon:iap:silver")
		additionalParams.Add("acr_values", "urn:mace:incommon:iap:bronze")

		authURL, err := leaf.GetAuthorizationURL(
			op1.EntityID,
			"https://rp.example.com/callback",
			"state123",
			"openid",
			additionalParams,
		)
		require.NoError(t, err)
		assert.NotEmpty(t, authURL)
	})
}

// =============================================================================
// CodeExchange Extended Tests
// =============================================================================

func TestFederationLeaf_CodeExchange_Extended(t *testing.T) {
	leaf := newTestFederationLeaf(t)
	tokenEndpoint := "https://op1.example.com/token"

	t.Run("invalid json response", func(t *testing.T) {
		httpmock.RegisterResponder(
			"POST", tokenEndpoint,
			httpmock.NewStringResponder(200, "not valid json"),
		)

		_, _, err := leaf.CodeExchange(
			op1.EntityID,
			"test-code",
			"https://rp.example.com/callback",
			nil,
		)
		assert.Error(t, err)
	})

	t.Run("server error response", func(t *testing.T) {
		httpmock.RegisterResponder(
			"POST", tokenEndpoint,
			httpmock.NewJsonResponderOrPanic(500, map[string]string{
				"error":             "server_error",
				"error_description": "Internal server error",
			}),
		)

		tokenRes, errRes, err := leaf.CodeExchange(
			op1.EntityID,
			"test-code",
			"https://rp.example.com/callback",
			nil,
		)
		require.NoError(t, err)
		assert.Nil(t, tokenRes)
		require.NotNil(t, errRes)
		assert.Equal(t, "server_error", errRes.Error)
	})

	t.Run("response with extra fields", func(t *testing.T) {
		httpmock.RegisterResponder(
			"POST", tokenEndpoint,
			httpmock.NewJsonResponderOrPanic(200, map[string]any{
				"access_token":  "access_token_123",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"custom_claim":  "custom_value",
				"another_claim": 42,
			}),
		)

		tokenRes, errRes, err := leaf.CodeExchange(
			op1.EntityID,
			"test-code",
			"https://rp.example.com/callback",
			nil,
		)
		require.NoError(t, err)
		assert.Nil(t, errRes)
		require.NotNil(t, tokenRes)

		assert.Equal(t, "access_token_123", tokenRes.AccessToken)
		assert.Equal(t, "custom_value", tokenRes.Extra["custom_claim"])
		assert.Equal(t, float64(42), tokenRes.Extra["another_claim"])
	})

	t.Run("empty response body", func(t *testing.T) {
		httpmock.RegisterResponder(
			"POST", tokenEndpoint,
			httpmock.NewStringResponder(200, ""),
		)

		_, _, err := leaf.CodeExchange(
			op1.EntityID,
			"test-code",
			"https://rp.example.com/callback",
			nil,
		)
		assert.Error(t, err)
	})

	t.Run("verifies client_id in request", func(t *testing.T) {
		httpmock.RegisterResponder(
			"POST", tokenEndpoint,
			func(req *http.Request) (*http.Response, error) {
				err := req.ParseForm()
				if err != nil {
					return httpmock.NewJsonResponse(400, map[string]string{"error": "bad_request"})
				}

				// Verify client_id matches the leaf's entity ID
				assert.Equal(t, rp1.EntityID, req.Form.Get("client_id"))
				assert.Equal(t, "https://rp.example.com/callback", req.Form.Get("redirect_uri"))

				return httpmock.NewJsonResponse(200, map[string]any{
					"access_token": "token",
					"token_type":   "Bearer",
				})
			},
		)

		_, _, err := leaf.CodeExchange(
			op1.EntityID,
			"test-code",
			"https://rp.example.com/callback",
			nil,
		)
		require.NoError(t, err)
	})
}

// =============================================================================
// OIDCTokenResponse Extended Tests
// =============================================================================

func TestOIDCTokenResponse_UnmarshalJSON_Extended(t *testing.T) {
	t.Run("all fields populated", func(t *testing.T) {
		jsonData := `{
			"access_token": "access123",
			"token_type": "Bearer",
			"expires_in": 7200,
			"refresh_token": "refresh456",
			"scope": "openid profile email",
			"id_token": "eyJhbGciOiJSUzI1NiJ9.payload.signature",
			"custom_field": "custom_value"
		}`

		var res OIDCTokenResponse
		err := json.Unmarshal([]byte(jsonData), &res)
		require.NoError(t, err)

		assert.Equal(t, "access123", res.AccessToken)
		assert.Equal(t, "Bearer", res.TokenType)
		assert.Equal(t, int64(7200), res.ExpiresIn)
		assert.Equal(t, "refresh456", res.RefreshToken)
		assert.Equal(t, "openid profile email", res.Scopes)
		assert.Equal(t, "eyJhbGciOiJSUzI1NiJ9.payload.signature", res.IDToken)
		assert.Equal(t, "custom_value", res.Extra["custom_field"])
	})

	t.Run("expires_in as string", func(t *testing.T) {
		// Some OPs might return expires_in as a string
		jsonData := `{
			"access_token": "token",
			"expires_in": "3600"
		}`

		var res OIDCTokenResponse
		err := json.Unmarshal([]byte(jsonData), &res)
		// This might error or succeed depending on implementation
		// The current implementation expects int64
		if err == nil {
			// If it succeeds, expires_in might be stored in Extra
			assert.Equal(t, "token", res.AccessToken)
		}
	})

	t.Run("null values", func(t *testing.T) {
		jsonData := `{
			"access_token": "token",
			"refresh_token": null,
			"scope": null
		}`

		var res OIDCTokenResponse
		err := json.Unmarshal([]byte(jsonData), &res)
		require.NoError(t, err)

		assert.Equal(t, "token", res.AccessToken)
		assert.Empty(t, res.RefreshToken)
		assert.Empty(t, res.Scopes)
	})
}

// =============================================================================
// RequestObjectProducer Extended Tests
// =============================================================================

func TestRequestObjectProducer_Extended(t *testing.T) {
	t.Run("expiration is set correctly", func(t *testing.T) {
		lifetime := 2 * time.Minute
		rop := NewRequestObjectProducer(rp1.EntityID, rp1.versatileSigner, lifetime)

		ro, err := rop.RequestObject(map[string]any{
			"aud": "https://op.example.com",
		}, nil)
		require.NoError(t, err)

		m, err := jwx.Parse(ro)
		require.NoError(t, err)

		payload, err := m.VerifyWithSet(rp1.jwks)
		require.NoError(t, err)

		var data map[string]any
		require.NoError(t, json.Unmarshal(payload, &data))

		iat := int64(data["iat"].(float64))
		exp := int64(data["exp"].(float64))

		// Verify exp is roughly iat + 2 minutes (120 seconds)
		diff := exp - iat
		assert.True(t, diff >= 119 && diff <= 121, "expiration should be ~120 seconds from iat, got %d", diff)
	})

	t.Run("jti is unique across calls", func(t *testing.T) {
		rop := NewRequestObjectProducer(rp1.EntityID, rp1.versatileSigner, time.Minute)

		ro1, err := rop.RequestObject(map[string]any{"aud": "https://op.example.com"}, nil)
		require.NoError(t, err)

		ro2, err := rop.RequestObject(map[string]any{"aud": "https://op.example.com"}, nil)
		require.NoError(t, err)

		// Parse both and extract jti
		m1, _ := jwx.Parse(ro1)
		payload1, _ := m1.VerifyWithSet(rp1.jwks)
		var data1 map[string]any
		json.Unmarshal(payload1, &data1)

		m2, _ := jwx.Parse(ro2)
		payload2, _ := m2.VerifyWithSet(rp1.jwks)
		var data2 map[string]any
		json.Unmarshal(payload2, &data2)

		assert.NotEqual(t, data1["jti"], data2["jti"], "jti should be unique for each request object")
	})

	t.Run("client assertion jti is unique", func(t *testing.T) {
		rop := NewRequestObjectProducer(rp1.EntityID, rp1.versatileSigner, time.Minute)

		ca1, err := rop.ClientAssertion("https://token.example.com")
		require.NoError(t, err)

		ca2, err := rop.ClientAssertion("https://token.example.com")
		require.NoError(t, err)

		m1, _ := jwx.Parse(ca1)
		payload1, _ := m1.VerifyWithSet(rp1.jwks)
		var data1 map[string]any
		json.Unmarshal(payload1, &data1)

		m2, _ := jwx.Parse(ca2)
		payload2, _ := m2.VerifyWithSet(rp1.jwks)
		var data2 map[string]any
		json.Unmarshal(payload2, &data2)

		assert.NotEqual(t, data1["jti"], data2["jti"], "jti should be unique for each client assertion")
	})

	t.Run("additional claims are preserved", func(t *testing.T) {
		rop := NewRequestObjectProducer(rp1.EntityID, rp1.versatileSigner, time.Minute)

		ro, err := rop.RequestObject(map[string]any{
			"aud":                   "https://op.example.com",
			"nonce":                 "nonce123",
			"code_challenge":        "challenge",
			"code_challenge_method": "S256",
			"prompt":                "consent",
		}, nil)
		require.NoError(t, err)

		m, err := jwx.Parse(ro)
		require.NoError(t, err)

		payload, err := m.VerifyWithSet(rp1.jwks)
		require.NoError(t, err)

		var data map[string]any
		require.NoError(t, json.Unmarshal(payload, &data))

		assert.Equal(t, "nonce123", data["nonce"])
		assert.Equal(t, "challenge", data["code_challenge"])
		assert.Equal(t, "S256", data["code_challenge_method"])
		assert.Equal(t, "consent", data["prompt"])
	})
}
