package oidfed

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jwxi "github.com/go-oidfed/lib/internal/jwx"
	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/kms"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/go-oidfed/lib/unixtime"
)

// mockLighthouseTarget is a minimal mock that publishes the jwks update
// endpoints in its federation_entity metadata Extra map, mimicking a
// lighthouse entity configuration.
type mockLighthouseTarget struct {
	entityID             string
	jwksUpdateURL        string
	jwksUpdateTriggerURL string
	// triggerAuthMethods, when non-nil, is published as
	// federation_jwks_update_trigger_endpoint_auth_methods. When nil/empty the
	// trigger endpoint is advertised as requiring no client auth.
	triggerAuthMethods []string
	signer             *jwx.EntityStatementSigner
	jwks               jwx.JWKS
}

func (m *mockLighthouseTarget) EntityConfigurationJWT() ([]byte, error) {
	now := time.Now()
	extra := map[string]any{
		oidfedconst.FederationJWKSUpdateEndpoint:        m.jwksUpdateURL,
		oidfedconst.FederationJWKSUpdateTriggerEndpoint: m.jwksUpdateTriggerURL,
	}
	if len(m.triggerAuthMethods) > 0 {
		extra[oidfedconst.FederationJWKSUpdateTriggerEndpointAuthMethods] = m.triggerAuthMethods
	}
	fedMeta := &FederationEntityMetadata{
		Extra:                                 extra,
		EndpointAuthSigningAlgValuesSupported: []string{"RS256", "ES256"},
	}
	payload := EntityStatementPayload{
		Issuer:    m.entityID,
		Subject:   m.entityID,
		IssuedAt:  unixtime.Unixtime{Time: now},
		ExpiresAt: unixtime.Unixtime{Time: now.Add(time.Hour)},
		JWKS:      m.jwks,
		Metadata:  &Metadata{FederationEntity: fedMeta},
	}
	return m.signer.JWT(&payload)
}

func newMockLighthouseTarget(t *testing.T, entityID, jwksUpdateURL, triggerURL string) *mockLighthouseTarget {
	t.Helper()
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	jwks, err := jwx.KeyToJWKS(sk.Public(), jwa.ES512())
	require.NoError(t, err)
	return &mockLighthouseTarget{
		entityID:             entityID,
		jwksUpdateURL:        jwksUpdateURL,
		jwksUpdateTriggerURL: triggerURL,
		signer:               jwx.NewEntityStatementSigner(jwx.NewSingleKeyVersatileSigner(sk, jwa.ES512())),
		jwks:                 jwks,
	}
}

// --- HTTPHook URLFunc tests ---

func TestHTTPHook_URLFunc(t *testing.T) {
	dynamicURL := "https://dynamic.example.com/hook"
	var (
		gotURL string
		mu     sync.Mutex
	)
	httpmock.RegisterResponder(
		"POST", dynamicURL,
		func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			gotURL = req.URL.String()
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := HTTPHook(
		HTTPHookConfig{
			URLFunc: func(_ context.Context, _ kms.KeyRotationEvent) (string, error) {
				return dynamicURL, nil
			},
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, dynamicURL, gotURL)
	mu.Unlock()
}

func TestHTTPHook_URLFunc_TakesPrecedenceOverURL(t *testing.T) {
	dynamicURL := "https://dynamic.example.com/hook"
	staticURL := "https://static.example.com/hook"
	var (
		gotURL string
		mu     sync.Mutex
	)
	httpmock.RegisterResponder(
		"POST", dynamicURL,
		func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			gotURL = req.URL.String()
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)
	// Register also for static URL to ensure it's NOT called.
	httpmock.RegisterResponder(
		"POST", staticURL,
		func(req *http.Request) (*http.Response, error) {
			t.Fatal("static URL should not have been called")
			return nil, nil
		},
	)

	hook, err := HTTPHook(
		HTTPHookConfig{
			URL: staticURL,
			URLFunc: func(_ context.Context, _ kms.KeyRotationEvent) (string, error) {
				return dynamicURL, nil
			},
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, dynamicURL, gotURL)
	mu.Unlock()
}

func TestHTTPHook_URLFunc_WithClientAuth_AudIsResolvedURL(t *testing.T) {
	dynamicURL := "https://dynamic.example.com/hook"
	sk := rsaTestSigningKey(t)
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())
	rop := NewRequestObjectProducer(testEntityID, signer, time.Minute)

	var (
		gotAssertion string
		mu           sync.Mutex
	)
	httpmock.RegisterResponder(
		"POST", dynamicURL,
		func(req *http.Request) (*http.Response, error) {
			form, err := url.ParseQuery(readBody(t, req))
			require.NoError(t, err)
			mu.Lock()
			gotAssertion = form.Get("client_assertion")
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := HTTPHook(
		HTTPHookConfig{
			URLFunc: func(_ context.Context, _ kms.KeyRotationEvent) (string, error) {
				return dynamicURL, nil
			},
			BodyMode: HTTPBodyNone,
			ClientAuth: &HTTPHookClientAuth{
				ROProducer: rop,
			},
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	require.NotEmpty(t, gotAssertion)
	// Parse the client assertion JWT and verify its aud is the resolved URL.
	parsed, err := jwxi.Parse([]byte(gotAssertion))
	require.NoError(t, err)
	var claims struct {
		Aud string `json:"aud"`
	}
	require.NoError(t, json.Unmarshal(parsed.Payload(), &claims))
	assert.Equal(t, dynamicURL, claims.Aud)
	mu.Unlock()
}

func TestHTTPHook_URLFunc_ErrorDoesNotError(t *testing.T) {
	hook, err := HTTPHook(
		HTTPHookConfig{
			URLFunc: func(_ context.Context, _ kms.KeyRotationEvent) (string, error) {
				return "", assertError("boom")
			},
		},
	)
	require.NoError(t, err)

	// Should return nil (logged), not propagate the error.
	require.NoError(t, hook(context.Background(), hookEvent(t)))
}

// --- HTTPHook ClientAuth.Algs tests ---

func TestHTTPHook_ClientAuth_WithAlgs(t *testing.T) {
	sk := rsaTestSigningKey(t)
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())
	rop := NewRequestObjectProducer(testEntityID, signer, time.Minute)

	var (
		gotAssertion string
		gotAlg       string
		mu           sync.Mutex
	)
	httpmock.RegisterResponder(
		"POST", testHookURL,
		func(req *http.Request) (*http.Response, error) {
			form, err := url.ParseQuery(readBody(t, req))
			require.NoError(t, err)
			mu.Lock()
			gotAssertion = form.Get("client_assertion")
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := HTTPHook(
		HTTPHookConfig{
			URL:      testHookURL,
			BodyMode: HTTPBodyNone,
			ClientAuth: &HTTPHookClientAuth{
				ROProducer: rop,
				Algs:       func() []string { return []string{"RS256", "ES256"} },
			},
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	require.NotEmpty(t, gotAssertion)
	parsed, err := jwxi.Parse([]byte(gotAssertion))
	require.NoError(t, err)
	alg, _ := parsed.Signatures()[0].ProtectedHeaders().Algorithm()
	assert.Equal(t, "RS256", alg.String())
	gotAlg = alg.String()
	mu.Unlock()
	_ = gotAlg
}

func TestHTTPHook_ClientAuth_WithAlgs_IncompatibleSkipsRequest(t *testing.T) {
	sk := rsaTestSigningKey(t)
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())
	rop := NewRequestObjectProducer(testEntityID, signer, time.Minute)

	hookCalled := false
	httpmock.RegisterResponder(
		"POST", testHookURL,
		func(req *http.Request) (*http.Response, error) {
			hookCalled = true
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := HTTPHook(
		HTTPHookConfig{
			URL:      testHookURL,
			BodyMode: HTTPBodyNone,
			ClientAuth: &HTTPHookClientAuth{
				ROProducer: rop,
				Algs:       func() []string { return []string{"ES256"} },
			},
		},
	)
	require.NoError(t, err)

	// The signer is RS256 but Algs only allows ES256. The assertion cannot be
	// created, so the request is skipped (nil error, logged).
	require.NoError(t, hook(context.Background(), hookEvent(t)))
	assert.False(t, hookCalled, "hook endpoint should not have been called")
}

// --- TriggerUpdateHook tests ---

func TestTriggerUpdateHook_ValidationErrors(t *testing.T) {
	t.Run(
		"missing target entity ID", func(t *testing.T) {
			_, err := TriggerUpdateHook(
				TriggerUpdateHookConfig{
					ROProducer: NewRequestObjectProducer(
						testEntityID, jwx.NewSingleKeyVersatileSigner(rsaTestSigningKey(t), jwa.RS256()), time.Minute,
					),
				},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "TargetEntityID is required")
		},
	)
	// ROProducer is optional: when nil the hook still constructs successfully
	// and dispatches to the no-auth variant.
	t.Run(
		"nil ROProducer is allowed", func(t *testing.T) {
			_, err := TriggerUpdateHook(
				TriggerUpdateHookConfig{
					TargetEntityID: "https://lh.example",
				},
			)
			require.NoError(t, err)
		},
	)
}

func TestTriggerUpdateHook_EndToEnd_WithAuth(t *testing.T) {
	lhEntityID := "https://lh-trigger-e2e.example"
	triggerURL := "https://lh-trigger-e2e.example/jwks-update-trigger"

	lh := newMockLighthouseTarget(t, lhEntityID, "https://lh-trigger-e2e.example/jwks-update", triggerURL)
	lh.triggerAuthMethods = []string{oidfedconst.AuthMethodPrivateKeyJWT}
	mockEntityConfiguration(lhEntityID, lh)

	sk := rsaTestSigningKey(t)
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())
	rop := NewRequestObjectProducer(testEntityID, signer, time.Minute)

	var (
		gotAssertion string
		gotSub       string
		mu           sync.Mutex
	)
	httpmock.RegisterResponder(
		"POST", triggerURL,
		func(req *http.Request) (*http.Response, error) {
			form, err := url.ParseQuery(readBody(t, req))
			require.NoError(t, err)
			mu.Lock()
			gotAssertion = form.Get("client_assertion")
			gotSub = form.Get("sub")
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := TriggerUpdateHook(
		TriggerUpdateHookConfig{
			TargetEntityID: lhEntityID,
			ROProducer:     rop,
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, testEntityID, gotSub)
	require.NotEmpty(t, gotAssertion)
	// Verify the assertion's aud is the trigger URL resolved from the EC.
	parsed, err := jwxi.Parse([]byte(gotAssertion))
	require.NoError(t, err)
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud string `json:"aud"`
	}
	require.NoError(t, json.Unmarshal(parsed.Payload(), &claims))
	assert.Equal(t, testEntityID, claims.Iss)
	assert.Equal(t, testEntityID, claims.Sub)
	assert.Equal(t, triggerURL, claims.Aud)
	// Verify the signing alg is RS256 (intersection of signer cap and EC algs
	// [RS256, ES256]).
	alg, _ := parsed.Signatures()[0].ProtectedHeaders().Algorithm()
	assert.Equal(t, "RS256", alg.String())
	mu.Unlock()
}

func TestTriggerUpdateHook_EndToEnd_WithoutAuth(t *testing.T) {
	lhEntityID := "https://lh-trigger-noauth.example"
	triggerURL := "https://lh-trigger-noauth.example/jwks-update-trigger"

	// Mock target does NOT set triggerAuthMethods → no auth required.
	lh := newMockLighthouseTarget(t, lhEntityID, "https://lh-trigger-noauth.example/jwks-update", triggerURL)
	mockEntityConfiguration(lhEntityID, lh)

	sk := rsaTestSigningKey(t)
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())
	rop := NewRequestObjectProducer(testEntityID, signer, time.Minute)

	var (
		gotAssertion string
		gotSub       string
		mu           sync.Mutex
	)
	httpmock.RegisterResponder(
		"POST", triggerURL,
		func(req *http.Request) (*http.Response, error) {
			form, err := url.ParseQuery(readBody(t, req))
			require.NoError(t, err)
			mu.Lock()
			gotAssertion = form.Get("client_assertion")
			gotSub = form.Get("sub")
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := TriggerUpdateHook(
		TriggerUpdateHookConfig{
			TargetEntityID: lhEntityID,
			ROProducer:     rop,
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	// No auth required → no client_assertion, but sub should still be sent.
	assert.Equal(t, testEntityID, gotSub)
	assert.Empty(t, gotAssertion, "no client_assertion should be sent when auth is not required")
	mu.Unlock()
}

func TestTriggerUpdateHook_EndToEnd_AuthRequiredButNoProducer(t *testing.T) {
	lhEntityID := "https://lh-trigger-noop.example"
	triggerURL := "https://lh-trigger-noop.example/jwks-update-trigger"

	// Target requires auth, but the hook is configured without an ROProducer.
	lh := newMockLighthouseTarget(t, lhEntityID, "https://lh-trigger-noop.example/jwks-update", triggerURL)
	lh.triggerAuthMethods = []string{oidfedconst.AuthMethodPrivateKeyJWT}
	mockEntityConfiguration(lhEntityID, lh)

	var (
		gotAssertion string
		gotSub       string
		mu           sync.Mutex
	)
	httpmock.RegisterResponder(
		"POST", triggerURL,
		func(req *http.Request) (*http.Response, error) {
			form, err := url.ParseQuery(readBody(t, req))
			require.NoError(t, err)
			mu.Lock()
			gotAssertion = form.Get("client_assertion")
			gotSub = form.Get("sub")
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := TriggerUpdateHook(
		TriggerUpdateHookConfig{
			TargetEntityID: lhEntityID,
			// ROProducer intentionally nil
		},
	)
	require.NoError(t, err)

	// Falls back to the no-auth variant (logged warning, not propagated).
	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, testEntityID, gotSub)
	assert.Empty(t, gotAssertion, "no client_assertion when ROProducer is nil even if auth required")
	mu.Unlock()
}

// --- JWKSUpdateHook tests ---

func TestJWKSUpdateHook_ValidationErrors(t *testing.T) {
	t.Run(
		"missing target entity ID", func(t *testing.T) {
			_, err := JWKSUpdateHook(
				JWKSUpdateHookConfig{
					Signer: jwx.NewSingleKeyVersatileSigner(rsaTestSigningKey(t), jwa.RS256()),
				},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "TargetEntityID is required")
		},
	)
	t.Run(
		"missing Signer", func(t *testing.T) {
			_, err := JWKSUpdateHook(
				JWKSUpdateHookConfig{
					TargetEntityID: "https://lh.example",
				},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "Signer is required")
		},
	)
}

func TestJWKSUpdateHook_EndToEnd(t *testing.T) {
	lhEntityID := "https://lh-jwks-e2e.example"
	jwksUpdateURL := "https://lh-jwks-e2e.example/jwks-update"

	lh := newMockLighthouseTarget(t, lhEntityID, jwksUpdateURL, "https://lh-jwks-e2e.example/jwks-update-trigger")
	mockEntityConfiguration(lhEntityID, lh)

	sk := rsaTestSigningKey(t)
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())

	var (
		gotBody string
		gotCT   string
		mu      sync.Mutex
	)
	httpmock.RegisterResponder(
		"POST", jwksUpdateURL,
		func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			gotBody = readBody(t, req)
			gotCT = req.Header.Get("Content-Type")
			mu.Unlock()
			return httpmock.NewStringResponse(204, ""), nil
		},
	)

	hook, err := JWKSUpdateHook(
		JWKSUpdateHookConfig{
			TargetEntityID: lhEntityID,
			Signer:         signer,
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, oidfedconst.ContentTypeJWKS, gotCT)
	// The body should be a valid signed JWKS JWT.
	signed, err := ParseSignedJWKS([]byte(gotBody))
	require.NoError(t, err)
	assert.Equal(t, testEntityID, signed.Issuer)
	assert.Equal(t, testEntityID, signed.Subject)
	assert.GreaterOrEqual(t, signed.Keys.Len(), 1)
	mu.Unlock()
}

// assertError is a tiny helper to return an error from a func.
type assertError string

func (e assertError) Error() string { return string(e) }
