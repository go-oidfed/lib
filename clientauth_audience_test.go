package oidfed

import (
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/oidfedconst"
)

// OpenID Federation 1.1 §8.8: the audience of a client authentication JWT
// MUST be the Entity Identifier of the entity whose federation endpoint is
// called, and the endpoint MUST NOT accept any other audience. These tests
// use endpoint URLs that differ from the entity identifiers so that an
// assertion addressed to the URL fails.

// captureAssertion registers a POST responder at endpoint that records the
// form's client_assertion and answers with body.
func captureAssertion(t *testing.T, endpoint, body string) func() (string, string) {
	t.Helper()
	var (
		mu           sync.Mutex
		assertion    string
		assertionTyp string
	)
	httpmock.RegisterResponder(
		http.MethodPost, endpoint,
		func(req *http.Request) (*http.Response, error) {
			form, err := url.ParseQuery(readBody(t, req))
			require.NoError(t, err)
			mu.Lock()
			assertion = form.Get("client_assertion")
			assertionTyp = form.Get("client_assertion_type")
			mu.Unlock()
			return httpmock.NewStringResponse(200, body), nil
		},
	)
	return func() (string, string) {
		mu.Lock()
		defer mu.Unlock()
		return assertion, assertionTyp
	}
}

func assertAudience(t *testing.T, got func() (string, string), wantAud, endpoint string) {
	t.Helper()
	assertion, assertionTyp := got()
	require.NotEmpty(t, assertion, "no client assertion was POSTed")
	assert.Equal(t, oidfedconst.OAuthClientAssertionJWTBearer, assertionTyp)
	claims, err := parseClientAssertionClaims(t, assertion)
	require.NoError(t, err)
	assert.Equal(t, wantAud, claims["aud"], "aud must be the called entity's identifier")
	assert.NotEqual(t, endpoint, claims["aud"], "aud must not be the endpoint URL")
	assert.Equal(t, testClientAuth, claims["iss"])
	assert.Equal(t, testClientAuth, claims["sub"])
}

func useDefaultClientAuth(t *testing.T) {
	t.Helper()
	prev := DefaultClientAuth
	t.Cleanup(func() { DefaultClientAuth = prev })
	SetDefaultClientAuth(clientAuthTestProducer(t))
}

func privateKeyJWT() []string {
	return []string{string(oidfedconst.AuthMethodPrivateKeyJWT)}
}

func TestClientAuthAudience_Fetch(t *testing.T) {
	useDefaultClientAuth(t)
	const issuer = "https://aud-fetch-issuer.example"
	const fetchEndpoint = "https://aud-fetch-issuer.example/federation/fetch"
	got := captureAssertion(t, fetchEndpoint, "")
	fe := &FederationEntityMetadata{
		FederationFetchEndpoint:            fetchEndpoint,
		FederationFetchEndpointAuthMethods: privateKeyJWT(),
	}

	// The response is not an entity statement; only the request matters.
	_, _ = FetchEntityStatement(fetchEndpoint, "https://aud-fetch-sub.example", issuer, fe)

	assertAudience(t, got, issuer, fetchEndpoint)
}

func TestClientAuthAudience_List(t *testing.T) {
	useDefaultClientAuth(t)
	const authorityID = "https://aud-list-authority.example"
	a := newMockAuthority(
		authorityID, EntityStatementPayload{
			Metadata: &Metadata{
				FederationEntity: &FederationEntityMetadata{
					FederationListEndpointAuthMethods: privateKeyJWT(),
				},
			},
		},
	)
	got := captureAssertion(t, a.ListEndpoint, "[]")

	collector := &SimpleEntityCollector{}
	_, _ = collector.CollectEntities(apimodel.EntityCollectionRequest{TrustAnchor: authorityID})

	assertAudience(t, got, authorityID, a.ListEndpoint)
}

func TestClientAuthAudience_TrustMark(t *testing.T) {
	useDefaultClientAuth(t)
	const issuerID = "https://aud-tm-issuer.example"
	const trustMarkEndpoint = "https://aud-tm-issuer.example/federation/trustmark"
	newMockAuthority(
		issuerID, EntityStatementPayload{
			Metadata: &Metadata{
				FederationEntity: &FederationEntityMetadata{
					FederationTrustMarkEndpoint:            trustMarkEndpoint,
					FederationTrustMarkEndpointAuthMethods: privateKeyJWT(),
				},
			},
		},
	)
	got := captureAssertion(t, trustMarkEndpoint, "")

	c := &EntityConfigurationTrustMarkConfig{
		TrustMarkType:   "https://aud-tm-issuer.example/tm/member",
		TrustMarkIssuer: issuerID,
		sub:             testClientAuth,
	}
	// The response is not a trust mark; only the request matters.
	_, _, _ = c.refreshExternal()

	assertAudience(t, got, issuerID, trustMarkEndpoint)
}

func TestClientAuthAudience_RemoteResolve(t *testing.T) {
	const taID = "https://aud-resolve-ta.example"
	const resolveEndpoint = "https://aud-resolve-ta.example/federation/resolve"
	newMockAuthority(
		taID, EntityStatementPayload{
			Metadata: &Metadata{
				FederationEntity: &FederationEntityMetadata{
					FederationResolveEndpoint:            resolveEndpoint,
					FederationResolveEndpointAuthMethods: privateKeyJWT(),
				},
			},
		},
	)
	got := captureAssertion(t, resolveEndpoint, "")

	r := SmartRemoteMetadataResolver{
		ClientAuth: &RemoteResolverClientAuth{ROProducer: clientAuthTestProducer(t)},
	}
	_, _ = r.ResolveResponsePayload(
		apimodel.ResolveRequest{
			Subject:     "https://aud-resolve-sub.example",
			TrustAnchor: []string{taID},
		},
	)

	assertAudience(t, got, taID, resolveEndpoint)
}
