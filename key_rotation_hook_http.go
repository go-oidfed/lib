package oidfed

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/pkg/errors"

	log "github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/internal/http"
	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/kms"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/go-oidfed/lib/unixtime"
)

const (
	defaultHTTPHookTimeout = 20 * time.Second
	defaultSignedJWKSLife  = 10 * time.Minute
)

// HTTPHookBodyMode selects what is sent in the body of the HTTP request
// triggered by an HTTPHook.
type HTTPHookBodyMode string

const (
	// HTTPBodyNone sends no body.
	HTTPBodyNone HTTPHookBodyMode = "none"
	// HTTPBodyEntityID sends the entity's entity_id as the "sub" form field
	// (content-type application/x-www-form-urlencoded).
	HTTPBodyEntityID HTTPHookBodyMode = "entity_id"
	// HTTPBodyJWKS sends the new JWKS as JSON (content-type
	// application/jwk-set+json).
	HTTPBodyJWKS HTTPHookBodyMode = "jwks"
	// HTTPBodySignedJWKS sends a signed JWK Set JWT (jwk-set+jwt) containing
	// the new JWKS in the "keys" claim. Requires Signer to be configured.
	HTTPBodySignedJWKS HTTPHookBodyMode = "signed_jwks"
)

// HTTPHookClientAuth configures private_key_jwt client authentication for the
// HTTP hook. The client assertion JWT is produced by the configured
// RequestObjectProducer (via ClientAssertion) and sent as the
// "client_assertion" and "client_assertion_type" form parameters in the
// request body — no token endpoint exchange is involved. The audience
// (aud claim) of the assertion is the hook URL.
//
// ClientAuth is incompatible with HTTPBodyJWKS and HTTPBodySignedJWKS (both
// use a non-form body); HTTPHook returns a construction error if they are
// combined.
type HTTPHookClientAuth struct {
	// ROProducer produces the client assertion JWT (private_key_jwt).
	ROProducer *RequestObjectProducer
	// Algs, if non-nil, returns the signature algorithms acceptable to the
	// target endpoint (e.g. read from the target's Entity Configuration
	// endpoint_auth_signing_alg_values_supported). The producer's signer
	// selects the first compatible algorithm from this list; if none match the
	// available signing keys the request is skipped with a logged error. If
	// nil, the producer's DefaultSigner is used.
	Algs func() []string
}

// HTTPHookConfig configures an HTTP key rotation hook.
type HTTPHookConfig struct {
	// URL is the URL to send the request to. Either URL or URLFunc must be
	// set; URLFunc takes precedence when both are provided.
	URL string
	// URLFunc, if non-nil, resolves the request URL dynamically per
	// invocation (e.g. by reading the target's Entity Configuration). It takes
	// precedence over URL. The resolved URL is also used as the audience
	// (aud claim) of any client assertion produced via ClientAuth.
	URLFunc func(ctx context.Context, event kms.KeyRotationEvent) (string, error)
	// Method is the HTTP method. Default: POST.
	Method string
	// BodyMode selects what is sent in the request body. Default: none.
	BodyMode HTTPHookBodyMode
	// Headers are additional headers set on the request.
	Headers map[string]string
	// Timeout is the HTTP client timeout. Default: 20s.
	Timeout time.Duration

	// ClientAuth enables private_key_jwt client authentication. When set, a
	// client assertion JWT is minted on each request and sent as the
	// "client_assertion" and "client_assertion_type" form parameters in the
	// request body. The assertion's audience is the hook URL. Incompatible
	// with HTTPBodyJWKS and HTTPBodySignedJWKS.
	ClientAuth *HTTPHookClientAuth

	// Signer is required when BodyMode is signed_jwks. It is used to mint the
	// jwk-set+jwt.
	Signer jwx.VersatileSigner
	// JWTLifetime is the lifetime (exp - iat) of the signed JWKS JWT.
	// Default: 10 minutes.
	JWTLifetime time.Duration
}

// HTTPHook returns a kms.KeyRotationHook that sends an HTTP request on key
// rotation. It validates the configuration at construction time and returns an
// error if required fields are missing or inconsistent.
func HTTPHook(cfg HTTPHookConfig) (kms.KeyRotationHook, error) {
	if cfg.URL == "" && cfg.URLFunc == nil {
		return nil, errors.New("HTTPHook: URL or URLFunc is required")
	}
	if cfg.Method == "" {
		cfg.Method = "POST"
	}
	if cfg.BodyMode == "" {
		cfg.BodyMode = HTTPBodyNone
	}
	if cfg.BodyMode == HTTPBodySignedJWKS && cfg.Signer == nil {
		return nil, errors.New("HTTPHook: Signer is required when BodyMode is signed_jwks")
	}
	if cfg.ClientAuth != nil {
		if cfg.ClientAuth.ROProducer == nil {
			return nil, errors.New("HTTPHook: ClientAuth.ROProducer is required")
		}
		if cfg.BodyMode == HTTPBodyJWKS || cfg.BodyMode == HTTPBodySignedJWKS {
			return nil, errors.Errorf(
				"HTTPHook: ClientAuth is incompatible with BodyMode %q (form body conflict)", cfg.BodyMode,
			)
		}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultHTTPHookTimeout
	}
	if cfg.JWTLifetime == 0 {
		cfg.JWTLifetime = defaultSignedJWKSLife
	}

	hook := &httpHook{
		cfg: cfg,
	}

	return hook.run, nil
}

type httpHook struct {
	cfg HTTPHookConfig
}

func (h *httpHook) run(ctx context.Context, event kms.KeyRotationEvent) error {
	if h.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.cfg.Timeout)
		defer cancel()
	}

	// Resolve the request URL. URLFunc takes precedence over the static URL.
	hookURL := h.cfg.URL
	if h.cfg.URLFunc != nil {
		resolved, rErr := h.cfg.URLFunc(ctx, event)
		if rErr != nil {
			log.Logger().Error().Err(rErr).
				Str("entity_id", event.EntityID).
				Msg("key rotation http hook: could not resolve URL")
			return nil
		}
		hookURL = resolved
	}
	if hookURL == "" {
		log.Logger().Error().
			Str("entity_id", event.EntityID).
			Msg("key rotation http hook: resolved URL is empty")
		return nil
	}

	req := http.Do().R().SetContext(ctx)
	for k, v := range h.cfg.Headers {
		req.SetHeader(k, v)
	}

	// Build the request body. ClientAuth and HTTPBodyEntityID both use a
	// form-encoded body (application/x-www-form-urlencoded). The JWKS and
	// signed-JWKS modes use their own content types and are incompatible with
	// ClientAuth (validated at construction time).
	var formBody url.Values
	var rawBody []byte
	contentType := ""

	if h.cfg.ClientAuth != nil || h.cfg.BodyMode == HTTPBodyEntityID {
		formBody = url.Values{}
		if h.cfg.BodyMode == HTTPBodyEntityID {
			formBody.Set("sub", event.EntityID)
		}
		if h.cfg.ClientAuth != nil {
			var algs []string
			if h.cfg.ClientAuth.Algs != nil {
				algs = h.cfg.ClientAuth.Algs()
			}
			assertion, aErr := h.cfg.ClientAuth.ROProducer.ClientAssertion(hookURL, algs...)
			if aErr != nil {
				log.Logger().Error().Err(aErr).
					Str("entity_id", event.EntityID).
					Str("url", hookURL).
					Msg("key rotation http hook: could not create client assertion")
				return nil
			}
			formBody.Set("client_assertion_type", oidfedconst.OAuthClientAssertionJWTBearer)
			formBody.Set("client_assertion", string(assertion))
		}
	} else {
		var bErr error
		switch h.cfg.BodyMode {
		case HTTPBodyNone:
			// no body
		case HTTPBodyJWKS:
			contentType = oidfedconst.ContentTypeJWKSetJSON
			rawBody, bErr = event.NewJWKS.MarshalJSON()
		case HTTPBodySignedJWKS:
			contentType = oidfedconst.ContentTypeJWKS
			rawBody, bErr = h.mintSignedJWKS(event)
		default:
			return errors.Errorf("key rotation http hook: unknown BodyMode %q", h.cfg.BodyMode)
		}
		if bErr != nil {
			log.Logger().Error().Err(bErr).
				Str("entity_id", event.EntityID).
				Str("url", hookURL).
				Msg("key rotation http hook: could not build request body")
			return nil
		}
	}

	if formBody != nil {
		req.SetFormDataFromValues(formBody)
	} else if rawBody != nil {
		req.SetBody(rawBody)
		req.SetHeader("Content-Type", contentType)
	}

	resp, err := req.Execute(h.cfg.Method, hookURL)
	if err != nil {
		log.Logger().Error().Err(err).
			Str("entity_id", event.EntityID).
			Str("url", hookURL).
			Str("method", h.cfg.Method).
			Msg("key rotation http hook: request failed")
		return nil
	}
	if resp.IsError() {
		log.Logger().Error().
			Int("status", resp.StatusCode()).
			Str("entity_id", event.EntityID).
			Str("url", hookURL).
			Str("body", string(resp.Body())).
			Msg("key rotation http hook: server returned error status")
		return nil
	}

	log.Logger().Info().
		Str("entity_id", event.EntityID).
		Str("url", hookURL).
		Str("method", h.cfg.Method).
		Int("status", resp.StatusCode()).
		Strs("added_kids", event.AddedKIDs).
		Msg("key rotation http hook: request completed")
	return nil
}

func (h *httpHook) mintSignedJWKS(event kms.KeyRotationEvent) ([]byte, error) {
	now := time.Now()
	payload := signedJWKSPayload{
		Keys:      event.NewJWKS,
		Issuer:    event.EntityID,
		Subject:   event.EntityID,
		IssuedAt:  &unixtime.Unixtime{Time: now},
		ExpiresAt: &unixtime.Unixtime{Time: now.Add(h.cfg.JWTLifetime)},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal signed JWKS payload")
	}

	signer, alg := h.cfg.Signer.DefaultSigner()
	if signer == nil {
		return nil, errors.New("no compatible signing key for signed JWKS")
	}
	signed, err := jwx.SignWithType(payloadBytes, nil, oidfedconst.JWTTypeJWKS, alg, signer)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign JWKS")
	}
	return signed, nil
}
