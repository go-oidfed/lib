package oidfed

import (
	"crypto"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/jwx"
)

// OIDCErrorResponse is the error response of an oidc provider
type OIDCErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// OIDCTokenResponse is the token response of an oidc provider
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scopes       string `json:"scope"`
	IDToken      string `json:"id_token"`

	Extra map[string]any `json:"-"`
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (res *OIDCTokenResponse) UnmarshalJSON(data []byte) error {
	type oidcTokenResponse OIDCTokenResponse
	r := oidcTokenResponse(*res)
	extra, err := unmarshalWithExtra(data, &r)
	if err != nil {
		return err
	}
	r.Extra = extra
	*res = OIDCTokenResponse(r)
	return nil
}

// RequestObjectProducer is a generator for signed request objects
type RequestObjectProducer struct {
	EntityID string
	lifetime time.Duration
	signer   jwx.VersatileSigner
}

// NewRequestObjectProducer creates a new RequestObjectProducer with the passed properties
func NewRequestObjectProducer(
	entityID string, multiSigner jwx.VersatileSigner, lifetime time.Duration,
) *RequestObjectProducer {
	return &RequestObjectProducer{
		EntityID: entityID,
		lifetime: lifetime,
		signer:   multiSigner,
	}
}

// RequestObject generates a signed request object jwt from the passed requestValues
func (rop RequestObjectProducer) RequestObject(requestValues map[string]any, alg ...string) (
	[]byte, error,
) {
	if requestValues == nil {
		return nil, errors.New("request must contain 'aud' claim with OPs issuer identifier url")
	}
	if _, audFound := requestValues["aud"]; !audFound {
		return nil, errors.New("request must contain 'aud' claim with OPs issuer identifier url")
	}
	requestValues["iss"] = rop.EntityID
	requestValues["client_id"] = rop.EntityID
	delete(requestValues, "sub")
	delete(requestValues, "client_secret")
	if _, jtiFound := requestValues["jti"]; !jtiFound {
		jti, err := uuid.NewRandom()
		if err != nil {
			return nil, errors.Wrap(err, "could not create jti")
		}
		requestValues["jti"] = jti.String()
	}
	now := time.Now()
	requestValues["iat"] = now.Unix()
	requestValues["exp"] = now.Add(rop.lifetime).Unix()

	j, err := json.Marshal(requestValues)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal request object into JWT")
	}

	return rop.signPayload(j, alg...)
}

func (rop RequestObjectProducer) signPayload(data []byte, algs ...string) ([]byte, error) {
	var signer crypto.Signer
	var alg jwa.SignatureAlgorithm
	if len(algs) == 0 {
		signer, alg = rop.signer.DefaultSigner()
	} else {
		signer, alg = rop.signer.Signer(algs...)
	}
	if signer == nil {
		return nil, errors.New("no compatible signing key")
	}
	return jwx.SignPayload(data, alg, signer, nil)
}

// ClientAssertion creates a new signed client assertion jwt for the passed audience
func (rop RequestObjectProducer) ClientAssertion(aud string, alg ...string) ([]byte, error) {
	now := time.Now()
	assertionValues := map[string]any{
		"iss": rop.EntityID,
		"sub": rop.EntityID,
		"iat": now.Unix(),
		"exp": now.Add(rop.lifetime).Unix(),
		"aud": aud,
	}
	jti, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "could not create jti")
	}
	assertionValues["jti"] = jti.String()

	j, err := json.Marshal(assertionValues)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal client assertion into JWT")
	}

	return rop.signPayload(j, alg...)
}

// GetAuthorizationURL creates an authorization url
func (f FederationLeaf) GetAuthorizationURL(
	issuer, redirectURI, state, scope string, additionalParams url.Values,
) (string, error) {
	opMetadata, err := f.ResolveOPMetadata(issuer)
	if err != nil {
		return "", err
	}
	requestParams := map[string]any{}
	for k, v := range additionalParams {
		if len(v) == 1 {
			requestParams[k] = v[0]
		} else {
			requestParams[k] = v
		}
	}
	requestParams["aud"] = opMetadata.Issuer
	requestParams["redirect_uri"] = redirectURI
	requestParams["state"] = state
	requestParams["response_type"] = "code"
	requestParams["scope"] = scope

	requestObject, err := f.oidcROProducer.RequestObject(
		requestParams, opMetadata.RequestObjectSignedResponseAlgValuesSupported...,
	)
	if err != nil {
		return "", errors.Wrap(err, "could not create request object")
	}
	u, err := url.Parse(opMetadata.AuthorizationEndpoint)
	if err != nil {
		return "", errors.WithStack(err)
	}
	q := url.Values{}
	q.Set("request", string(requestObject))
	q.Set("client_id", f.EntityID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// CodeExchange performs an oidc code exchange it creates the mytoken and stores it in the database
func (f FederationLeaf) CodeExchange(
	issuer, code, redirectURI string,
	additionalParameter url.Values,
) (*OIDCTokenResponse, *OIDCErrorResponse, error) {
	opMetadata, err := f.ResolveOPMetadata(issuer)
	if err != nil {
		return nil, nil, err
	}
	params := additionalParameter
	if params == nil {
		params = url.Values{}
	}
	params.Set("grant_type", "authorization_code")
	params.Set("code", code)
	params.Set("redirect_uri", redirectURI)
	params.Set("client_id", f.EntityID)

	clientAssertion, err := f.oidcROProducer.ClientAssertion(
		opMetadata.TokenEndpoint,
		opMetadata.TokenEndpointAuthSigningAlgValuesSupported...,
	)
	if err != nil {
		return nil, nil, err
	}
	params.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	params.Set("client_assertion", string(clientAssertion))

	res, err := http.PostForm(opMetadata.TokenEndpoint, params)
	if err != nil {
		return nil, nil, err
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, nil, err
	}
	var errRes OIDCErrorResponse
	var tokenRes OIDCTokenResponse
	if err = json.Unmarshal(body, &errRes); err != nil {
		return nil, nil, err
	}
	if errRes.Error != "" {
		return nil, &errRes, nil
	}
	if err = json.Unmarshal(body, &tokenRes); err != nil {
		return nil, nil, err
	}
	return &tokenRes, nil, nil
}
