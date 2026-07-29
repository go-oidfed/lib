package oidfed

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
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
)

const (
	testHookURL  = "https://hook.example.com/trigger"
	testEntityID = "https://entity.example"
)

func rsaTestSigningKey(t *testing.T) jwx.SigningKey {
	t.Helper()
	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return sk
}

func hookEvent(t *testing.T) kms.KeyRotationEvent {
	t.Helper()
	return kms.KeyRotationEvent{
		EntityID:  testEntityID,
		NewJWKS:   *createTestJWKS(t, "hook-kid"),
		AddedKIDs: []string{"hook-kid"},
	}
}

func readBody(t *testing.T, r *http.Request) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	return string(b)
}

func TestHTTPHook_BodyNone(t *testing.T) {
	var (
		gotMethod string
		gotBody   string
		mu        sync.Mutex
	)
	httpmock.RegisterResponder(
		"POST", testHookURL,
		func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			gotMethod = req.Method
			gotBody = readBody(t, req)
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := HTTPHook(HTTPHookConfig{URL: testHookURL})
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, "POST", gotMethod)
	assert.Empty(t, gotBody)
	mu.Unlock()
}

func TestHTTPHook_BodyEntityID(t *testing.T) {
	var (
		gotForm url.Values
		gotCT   string
		mu      sync.Mutex
	)
	httpmock.RegisterResponder(
		"POST", testHookURL,
		func(req *http.Request) (*http.Response, error) {
			body := readBody(t, req)
			form, err := url.ParseQuery(body)
			require.NoError(t, err)
			mu.Lock()
			gotForm = form
			gotCT = req.Header.Get("Content-Type")
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := HTTPHook(
		HTTPHookConfig{
			URL:      testHookURL,
			BodyMode: HTTPBodyEntityID,
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, "application/x-www-form-urlencoded", gotCT)
	assert.Equal(t, testEntityID, gotForm.Get("sub"))
	mu.Unlock()
}

func TestHTTPHook_BodyJWKS(t *testing.T) {
	var (
		gotBody string
		gotCT   string
		mu      sync.Mutex
	)
	httpmock.RegisterResponder(
		"POST", testHookURL,
		func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			gotBody = readBody(t, req)
			gotCT = req.Header.Get("Content-Type")
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := HTTPHook(
		HTTPHookConfig{
			URL:      testHookURL,
			BodyMode: HTTPBodyJWKS,
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, "application/jwk-set+json", gotCT)
	assert.Contains(t, gotBody, "hook-kid")
	assert.Contains(t, gotBody, "keys")
	mu.Unlock()
}

func TestHTTPHook_BodySignedJWKS(t *testing.T) {
	sk := rsaTestSigningKey(t)
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())

	var (
		gotBody string
		gotCT   string
		mu      sync.Mutex
	)
	httpmock.RegisterResponder(
		"POST", testHookURL,
		func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			gotBody = readBody(t, req)
			gotCT = req.Header.Get("Content-Type")
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := HTTPHook(
		HTTPHookConfig{
			URL:      testHookURL,
			BodyMode: HTTPBodySignedJWKS,
			Signer:   signer,
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, oidfedconst.ContentTypeJWKS, gotCT)
	assert.NotEmpty(t, gotBody, "body should contain signed JWT")
	mu.Unlock()

	// Parse and verify the signed JWKS JWT.
	parsed, err := ParseSignedJWKS([]byte(gotBody))
	require.NoError(t, err)
	assert.Equal(t, testEntityID, parsed.Issuer)
	assert.Equal(t, testEntityID, parsed.Subject)
	assert.Equal(t, 1, parsed.Keys.Len())

	// Verify signature against the signer's public JWKS.
	signerJWKS := publicJWKSFrom(t, sk)
	assert.True(t, parsed.Verify(signerJWKS), "signed JWKS signature should verify")
}

func TestHTTPHook_MethodOverride(t *testing.T) {
	var gotMethod string
	var mu sync.Mutex
	httpmock.RegisterResponder(
		"PUT", testHookURL,
		func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			gotMethod = req.Method
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := HTTPHook(
		HTTPHookConfig{
			URL:    testHookURL,
			Method: "PUT",
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, "PUT", gotMethod)
	mu.Unlock()
}

func TestHTTPHook_DefaultMethod(t *testing.T) {
	var gotMethod string
	var mu sync.Mutex
	httpmock.RegisterResponder(
		"POST", testHookURL,
		func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			gotMethod = req.Method
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := HTTPHook(HTTPHookConfig{URL: testHookURL})
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, "POST", gotMethod)
	mu.Unlock()
}

func TestHTTPHook_ClientAuth(t *testing.T) {
	sk := rsaTestSigningKey(t)
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())
	rop := NewRequestObjectProducer(testEntityID, signer, time.Minute)

	var (
		gotAssertion    string
		gotAssertionTyp string
		mu              sync.Mutex
	)

	httpmock.RegisterResponder(
		"POST", testHookURL,
		func(req *http.Request) (*http.Response, error) {
			form, err := url.ParseQuery(readBody(t, req))
			require.NoError(t, err)
			mu.Lock()
			gotAssertion = form.Get("client_assertion")
			gotAssertionTyp = form.Get("client_assertion_type")
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
			},
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, oidfedconst.OAuthClientAssertionJWTBearer, gotAssertionTyp)
	assert.NotEmpty(t, gotAssertion, "client_assertion should be present")
	mu.Unlock()

	// Parse the client assertion JWT and verify its claims.
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
	assert.Equal(t, testHookURL, claims.Aud)
}

func TestHTTPHook_ClientAuth_WithEntityID(t *testing.T) {
	sk := rsaTestSigningKey(t)
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())
	rop := NewRequestObjectProducer(testEntityID, signer, time.Minute)

	var (
		gotSub       string
		gotAssertion string
		mu           sync.Mutex
	)

	httpmock.RegisterResponder(
		"POST", testHookURL,
		func(req *http.Request) (*http.Response, error) {
			form, err := url.ParseQuery(readBody(t, req))
			require.NoError(t, err)
			mu.Lock()
			gotSub = form.Get("sub")
			gotAssertion = form.Get("client_assertion")
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	hook, err := HTTPHook(
		HTTPHookConfig{
			URL:      testHookURL,
			BodyMode: HTTPBodyEntityID,
			ClientAuth: &HTTPHookClientAuth{
				ROProducer: rop,
			},
		},
	)
	require.NoError(t, err)

	require.NoError(t, hook(context.Background(), hookEvent(t)))

	mu.Lock()
	assert.Equal(t, testEntityID, gotSub, "sub form field should be set")
	assert.NotEmpty(t, gotAssertion, "client_assertion should be present")
	mu.Unlock()
}

func TestHTTPHook_ErrorStatusDoesNotError(t *testing.T) {
	httpmock.RegisterResponder(
		"POST", testHookURL,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewStringResponse(500, "internal server error"), nil
		},
	)

	hook, err := HTTPHook(HTTPHookConfig{URL: testHookURL})
	require.NoError(t, err)

	err = hook(context.Background(), hookEvent(t))
	assert.NoError(t, err, "5xx should be logged, not returned")
}

func TestHTTPHook_ValidationErrors(t *testing.T) {
	t.Run(
		"missing URL", func(t *testing.T) {
			_, err := HTTPHook(HTTPHookConfig{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "URL or URLFunc is required")
		},
	)

	t.Run(
		"signed_jwks without signer", func(t *testing.T) {
			_, err := HTTPHook(
				HTTPHookConfig{
					URL:      testHookURL,
					BodyMode: HTTPBodySignedJWKS,
				},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "Signer is required")
		},
	)

	t.Run(
		"client auth without ROProducer", func(t *testing.T) {
			_, err := HTTPHook(
				HTTPHookConfig{
					URL:        testHookURL,
					ClientAuth: &HTTPHookClientAuth{},
				},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "ROProducer is required")
		},
	)

	t.Run(
		"client auth incompatible with jwks", func(t *testing.T) {
			_, err := HTTPHook(
				HTTPHookConfig{
					URL:      testHookURL,
					BodyMode: HTTPBodyJWKS,
					ClientAuth: &HTTPHookClientAuth{
						ROProducer: NewRequestObjectProducer(
							testEntityID, jwx.NewSingleKeyVersatileSigner(rsaTestSigningKey(t), jwa.RS256()), time.Minute,
						),
					},
				},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "incompatible")
		},
	)

	t.Run(
		"client auth incompatible with signed_jwks", func(t *testing.T) {
			_, err := HTTPHook(
				HTTPHookConfig{
					URL:      testHookURL,
					BodyMode: HTTPBodySignedJWKS,
					Signer:   jwx.NewSingleKeyVersatileSigner(rsaTestSigningKey(t), jwa.RS256()),
					ClientAuth: &HTTPHookClientAuth{
						ROProducer: NewRequestObjectProducer(
							testEntityID, jwx.NewSingleKeyVersatileSigner(rsaTestSigningKey(t), jwa.RS256()), time.Minute,
						),
					},
				},
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "incompatible")
		},
	)
}
