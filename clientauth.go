package oidfed

import (
	"net/url"

	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"

	internalhttp "github.com/go-oidfed/lib/internal/http"
	"github.com/go-oidfed/lib/oidfedconst"
)

// DefaultClientAuth supplies the RequestObjectProducer used to authenticate to
// federation endpoints when their *_auth_methods advertise private_key_jwt. It
// may be nil, meaning no client authentication is attempted (requests stay
// unauthenticated, current behavior).
//
// A caller may set this to apply automatic private_key_jwt client
// authentication to every federation endpoint the library calls (resolve,
// fetch, list, trust-mark) whose Entity Configuration advertises
// private_key_jwt in the endpoint's *_auth_methods field.
var DefaultClientAuth *RequestObjectProducer

// SetDefaultClientAuth sets the global DefaultClientAuth producer. Pass nil to
// disable automatic client authentication.
func SetDefaultClientAuth(p *RequestObjectProducer) {
	DefaultClientAuth = p
}

// clientAuthRequired reports whether the endpoint whose *_auth_methods field is
// given requires private_key_jwt client authentication.
func clientAuthRequired(authMethods []string) bool {
	for _, m := range authMethods {
		if m == oidfedconst.AuthMethodPrivateKeyJWT {
			return true
		}
	}
	return false
}

// clientAuthForm returns assertion fields (client_assertion_type and client_assertion) produced for
// the given audience by producer. It returns an error if the assertion cannot
// be minted. The returned values are suitable as a form-encoded POST body
// (application/x-www-form-urlencoded).
func clientAuthForm(params url.Values, producer *RequestObjectProducer, aud string, algs []string) (url.Values, error) {
	form := url.Values{}
	for k, vs := range params {
		form[k] = vs
	}
	assertion, err := producer.ClientAssertion(aud, algs...)
	if err != nil {
		return nil, err
	}
	form.Set("client_assertion_type", oidfedconst.OAuthClientAssertionJWTBearer)
	form.Set("client_assertion", string(assertion))
	return form, nil
}

// endpointAlgsFromEC returns the endpoint_auth_signing_alg_values_supported
// advertised by the given federation entity metadata, or nil.
func endpointAlgsFromEC(fe *FederationEntityMetadata) []string {
	if fe == nil {
		return nil
	}
	return fe.EndpointAuthSigningAlgValuesSupported
}

// httpFederationEndpointRequest issues a request to a federation endpoint
// (fetch/list/trust-mark) with automatic private_key_jwt client authentication
// when authMethods advertises private_key_jwt and DefaultClientAuth is set. In
// that case the params are sent as a form-encoded POST body together with the
// client assertion (audience = endpoint; signing algorithms read from algEC's
// endpoint_auth_signing_alg_values_supported when non-empty); otherwise an
// unauthenticated GET with the params as query string is used. result, if
// non-nil, is parsed from the response body. algEC may be nil, in which case
// the producer's default signer is used.
func httpFederationEndpointRequest(
	endpoint string, params url.Values, authMethods []string, algEC *FederationEntityMetadata, result interface{},
) (*resty.Response, *internalhttp.HttpError, error) {
	if clientAuthRequired(authMethods) && DefaultClientAuth != nil {
		form, err := clientAuthForm(params, DefaultClientAuth, endpoint, endpointAlgsFromEC(algEC))
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
		resp, err := internalhttp.Do().R().
			SetFormDataFromValues(form).
			SetError(&internalhttp.HttpError{}).
			SetResult(result).
			Post(endpoint)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
		if errRes, ok := resp.Error().(*internalhttp.HttpError); ok && errRes != nil && errRes.Error != "" {
			errRes.Status = resp.RawResponse.StatusCode
			return nil, errRes, nil
		}
		return resp, nil, nil
	}
	return internalhttp.Get(endpoint, params, result)
}
