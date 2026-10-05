package oidfed

import (
	"crypto/rand"
	"crypto/rsa"
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

	"github.com/go-oidfed/lib/apimodel"
	jwxi "github.com/go-oidfed/lib/internal/jwx"
	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/oidfedconst"
)

const (
	testResolveURL = "https://resolve.example.com/federation_resolve"
	testClientAuth = "https://auth.example"
	testResolveSub = "https://subject.example"
	testEndptAuth  = "https://endpoint.example/federation"
)

func clientAuthTestProducer(t *testing.T) *RequestObjectProducer {
	t.Helper()
	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := jwx.NewSingleKeyVersatileSigner(sk, jwa.RS256())
	return NewRequestObjectProducer(testClientAuth, signer, time.Minute)
}

func clientAuthTestRequest() apimodel.ResolveRequest {
	return apimodel.ResolveRequest{
		Subject:     testResolveSub,
		TrustAnchor: []string{"https://ta.example"},
	}
}

func parseClientAssertionClaims(t *testing.T, assertion string) (map[string]interface{}, error) {
	t.Helper()
	parsed, err := jwxi.Parse([]byte(assertion))
	if err != nil {
		return nil, err
	}
	claims := map[string]interface{}{}
	err = json.Unmarshal(parsed.Payload(), &claims)
	return claims, err
}

// TestResolveResponse_ClientAuthPOST verifies that a SimpleRemoteMetadataResolver
// with a non-nil ClientAuth producer POSTs the resolve params and a client
// assertion as a form body, with aud = the resolve endpoint URL, without
// consulting any entity configuration (the explicit-URL OFFA path).
func TestResolveResponse_ClientAuthPOST(t *testing.T) {
	rop := clientAuthTestProducer(t)
	var (
		gotMethod       string
		gotContentType  string
		gotAssertion    string
		gotAssertionTyp string
		mu              sync.Mutex
	)
	httpmock.RegisterResponder(
		http.MethodPost, testResolveURL,
		func(req *http.Request) (*http.Response, error) {
			form, err := url.ParseQuery(readBody(t, req))
			require.NoError(t, err)
			mu.Lock()
			gotMethod = req.Method
			gotContentType = req.Header.Get("Content-Type")
			gotAssertion = form.Get("client_assertion")
			gotAssertionTyp = form.Get("client_assertion_type")
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	r := SimpleRemoteMetadataResolver{
		ResolveEndpoint: testResolveURL,
		ClientAuth:      rop,
		Headers:         map[string]string{"X-Custom": "value"},
	}
	// Response body is not a valid resolve response; we only inspect the request.
	_, _, _ = r.ResolveResponse(clientAuthTestRequest())

	mu.Lock()
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Contains(t, gotContentType, "application/x-www-form-urlencoded")
	assert.Equal(t, oidfedconst.OAuthClientAssertionJWTBearer, gotAssertionTyp)
	require.NotEmpty(t, gotAssertion)
	mu.Unlock()

	claims, err := parseClientAssertionClaims(t, gotAssertion)
	require.NoError(t, err)
	assert.Equal(t, testClientAuth, claims["iss"])
	assert.Equal(t, testResolveURL, claims["aud"])
}

// TestResolveResponse_NoClientAuthGET verifies that without ClientAuth the
// resolve request stays an unauthenticated GET (unchanged behavior).
func TestResolveResponse_NoClientAuthGET(t *testing.T) {
	var (
		gotMethod string
		mu        sync.Mutex
	)
	httpmock.RegisterResponder(
		http.MethodGet, testResolveURL,
		func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			gotMethod = req.Method
			mu.Unlock()
			return httpmock.NewStringResponse(200, ""), nil
		},
	)

	r := SimpleRemoteMetadataResolver{ResolveEndpoint: testResolveURL}
	_, _, _ = r.ResolveResponse(clientAuthTestRequest())

	mu.Lock()
	assert.Equal(t, http.MethodGet, gotMethod)
	mu.Unlock()
}

// TestFederationEndpointRequest_ClientAuth covers the shared fetch/list/trust-mark
// dispatch helper. With private_key_jwt advertised and DefaultClientAuth set it
// POSTs a form containing the assertion; without private_key_jwt (or with no
// DefaultClientAuth) it GETs unchanged.
func TestFederationEndpointRequest_ClientAuth(t *testing.T) {
	var (
		gotMethod       string
		gotAssertion    string
		gotAssertionTyp string
		mu              sync.Mutex
	)
	httpmock.RegisterResponder(
		http.MethodPost, testEndptAuth,
		func(req *http.Request) (*http.Response, error) {
			form, err := url.ParseQuery(readBody(t, req))
			require.NoError(t, err)
			mu.Lock()
			gotMethod = req.Method
			gotAssertion = form.Get("client_assertion")
			gotAssertionTyp = form.Get("client_assertion_type")
			mu.Unlock()
			return httpmock.NewStringResponse(200, "[]"), nil
		},
	)
	httpmock.RegisterResponder(
		http.MethodGet, testEndptAuth,
		func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			gotMethod = req.Method
			gotAssertion = ""
			gotAssertionTyp = ""
			mu.Unlock()
			return httpmock.NewStringResponse(200, "[]"), nil
		},
	)

	rop := clientAuthTestProducer(t)
	fe := &FederationEntityMetadata{
		FederationFetchEndpointAuthMethods:    []string{string(oidfedconst.AuthMethodPrivateKeyJWT)},
		EndpointAuthSigningAlgValuesSupported: []string{"RS256"},
	}
	authMethods := []string{string(oidfedconst.AuthMethodPrivateKeyJWT)}

	prev := DefaultClientAuth
	t.Cleanup(func() { DefaultClientAuth = prev })

	// private_key_jwt advertised + DefaultClientAuth -> POST with assertion.
	DefaultClientAuth = rop
	_, errRes, err := httpFederationEndpointRequest(testEndptAuth, url.Values{"sub": {"s"}}, authMethods, fe, nil)
	require.NoError(t, err)
	require.Nil(t, errRes)
	mu.Lock()
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, oidfedconst.OAuthClientAssertionJWTBearer, gotAssertionTyp)
	require.NotEmpty(t, gotAssertion)
	mu.Unlock()

	claims, err := parseClientAssertionClaims(t, gotAssertion)
	require.NoError(t, err)
	assert.Equal(t, testClientAuth, claims["iss"])
	assert.Equal(t, testEndptAuth, claims["aud"])

	// Not advertised -> GET, unchanged.
	DefaultClientAuth = rop
	_, _, err = httpFederationEndpointRequest(testEndptAuth, url.Values{"sub": {"s"}}, nil, fe, nil)
	require.NoError(t, err)
	mu.Lock()
	assert.Equal(t, http.MethodGet, gotMethod)
	assert.Empty(t, gotAssertion)
	mu.Unlock()

	// Advertised but DefaultClientAuth nil -> GET, unchanged (no producer).
	DefaultClientAuth = nil
	_, _, err = httpFederationEndpointRequest(testEndptAuth, url.Values{"sub": {"s"}}, authMethods, fe, nil)
	require.NoError(t, err)
	mu.Lock()
	assert.Equal(t, http.MethodGet, gotMethod)
	mu.Unlock()
}

// TestRemoteResolverForTA_AuthAutoDiscovery verifies that SmartRemoteMetadataResolver
// authenticates to a TA's resolve endpoint exactly when the TA EC advertises
// private_key_jwt in federation_resolve_endpoint_auth_methods (or Force is
// set), and leaves auth disabled otherwise or without ClientAuth.
func TestRemoteResolverForTA_AuthAutoDiscovery(t *testing.T) {
	rop := clientAuthTestProducer(t)

	advertised := &FederationEntityMetadata{
		FederationResolveEndpointAuthMethods:  []string{string(oidfedconst.AuthMethodPrivateKeyJWT)},
		EndpointAuthSigningAlgValuesSupported: []string{"RS256"},
	}
	plain := &FederationEntityMetadata{}

	// Advertised -> producer set, AlgsFromEC reads EC algs.
	r := (SmartRemoteMetadataResolver{ClientAuth: &RemoteResolverClientAuth{ROProducer: rop}}).
		remoteResolverForTA(testResolveURL, advertised)
	assert.NotNil(t, r.ClientAuth)
	require.NotNil(t, r.AlgsFromEC)
	assert.Equal(t, []string{"RS256"}, r.AlgsFromEC())

	// Not advertised, Force=false -> no auth on the built SimpleRemote.
	r = (SmartRemoteMetadataResolver{ClientAuth: &RemoteResolverClientAuth{ROProducer: rop}}).
		remoteResolverForTA(testResolveURL, plain)
	assert.Nil(t, r.ClientAuth)
	require.NotNil(t, r.AlgsFromEC)

	// Not advertised but Force=true -> Force skips the advertisement check.
	r = (SmartRemoteMetadataResolver{
		ClientAuth: &RemoteResolverClientAuth{ROProducer: rop, Force: true},
	}).remoteResolverForTA(testResolveURL, plain)
	assert.NotNil(t, r.ClientAuth)

	// No ClientAuth on the smart resolver -> no ClientAuth on the SimpleRemote.
	r = (SmartRemoteMetadataResolver{}).remoteResolverForTA(testResolveURL, advertised)
	assert.Nil(t, r.ClientAuth)
	assert.Nil(t, r.AlgsFromEC)
}
