package oidfed

import (
	"context"
	"time"

	"github.com/pkg/errors"

	log "github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/kms"
	"github.com/go-oidfed/lib/oidfedconst"
)

// fetchTargetEC fetches the Entity Configuration of the target entity (cached
// via GetEntityConfiguration) and returns it. It is a small helper to avoid
// repeating the nil-check chain in every resolver func.
func fetchTargetEC(targetEntityID string) (*EntityStatement, error) {
	if targetEntityID == "" {
		return nil, errors.New("target entity id is empty")
	}
	stmt, err := GetEntityConfiguration(targetEntityID)
	if err != nil {
		return nil, errors.Wrapf(err, "could not fetch entity configuration for %q", targetEntityID)
	}
	if stmt == nil || stmt.Metadata == nil || stmt.Metadata.FederationEntity == nil {
		return nil, errors.Errorf("entity configuration for %q has no federation_entity metadata", targetEntityID)
	}
	return stmt, nil
}

// extraString reads a string value from the federation_entity metadata Extra
// map. Returns "" if the key is absent or not a string.
func extraString(fe *FederationEntityMetadata, key string) string {
	if fe == nil || fe.Extra == nil {
		return ""
	}
	v, _ := fe.Extra[key].(string)
	return v
}

// extraStringSlice reads a []string value from the federation_entity metadata
// Extra map. Returns nil if the key is absent. It also accepts []any (the
// natural JSON-decode shape) and coerces each element to a string.
func extraStringSlice(fe *FederationEntityMetadata, key string) []string {
	if fe == nil || fe.Extra == nil {
		return nil
	}
	switch v := fe.Extra[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// triggerAuthRequiredFromEC reads the target entity's Entity Configuration and
// reports whether the federation_jwks_update_trigger_endpoint requires
// private_key_jwt client authentication. The federating entity (e.g. a
// lighthouse) signals this by listing "private_key_jwt" in the
// federation_jwks_update_trigger_endpoint_auth_methods Extra field. When the
// field is absent, no client auth is required.
func triggerAuthRequiredFromEC(targetEntityID string) (bool, error) {
	stmt, err := fetchTargetEC(targetEntityID)
	if err != nil {
		return false, err
	}
	for _, m := range extraStringSlice(stmt.Metadata.FederationEntity, oidfedconst.FederationJWKSUpdateTriggerEndpointAuthMethods) {
		if m == oidfedconst.AuthMethodPrivateKeyJWT {
			return true, nil
		}
	}
	return false, nil
}

// resolveEndpointFromEC returns a URLFunc that resolves an endpoint URL from
// the target entity's Entity Configuration (federation_entity metadata Extra).
func resolveEndpointFromEC(targetEntityID, endpointKey, label string) func(context.Context, kms.KeyRotationEvent) (string, error) {
	return func(_ context.Context, _ kms.KeyRotationEvent) (string, error) {
		stmt, err := fetchTargetEC(targetEntityID)
		if err != nil {
			return "", err
		}
		url := extraString(stmt.Metadata.FederationEntity, endpointKey)
		if url == "" {
			return "", errors.Errorf(
				"entity configuration for %q does not advertise %q (%s)", targetEntityID, endpointKey, label,
			)
		}
		return url, nil
	}
}

// resolveAlgsFromEC returns an Algs func that reads the global
// endpoint_auth_signing_alg_values_supported from the target entity's Entity
// Configuration. Federating entities (e.g. a lighthouse) publish only this
// general list, not per-endpoint signing-alg lists.
func resolveAlgsFromEC(targetEntityID string) func() []string {
	return func() []string {
		stmt, err := fetchTargetEC(targetEntityID)
		if err != nil {
			log.Logger().Error().Err(err).
				Str("target_entity_id", targetEntityID).
				Msg("key rotation hook: could not read algs from target EC")
			return nil
		}
		return stmt.Metadata.FederationEntity.EndpointAuthSigningAlgValuesSupported
	}
}

// TriggerUpdateHookConfig configures a key rotation hook that POSTs to the
// target entity's federation_jwks_update_trigger_endpoint, telling it to
// re-fetch this entity's JWKS from its Entity Configuration. The endpoint URL
// and supported signing algorithms are read dynamically from the target's
// Entity Configuration on each rotation (served from the EC cache).
//
// Whether client authentication is used is decided per invocation from the
// target's EC: if it advertises private_key_jwt in
// federation_jwks_update_trigger_endpoint_auth_methods, the hook authenticates
// with ROProducer; otherwise it sends an unauthenticated request with the
// entity_id in the "sub" form field. If auth is required but ROProducer is
// nil, the request is sent without auth and will fail at the target (logged,
// not propagated).
type TriggerUpdateHookConfig struct {
	// TargetEntityID is the entity identifier of the federating entity (e.g.
	// a lighthouse) that exposes the trigger endpoint.
	TargetEntityID string
	// ROProducer produces the client assertion JWT (private_key_jwt) used to
	// authenticate to the trigger endpoint. Optional; when nil the hook never
	// authenticates, even if the target requires it.
	ROProducer *RequestObjectProducer
	// Headers are additional headers set on the request.
	Headers map[string]string
	// Timeout is the HTTP client timeout. Default: 20s.
	Timeout time.Duration
}

// TriggerUpdateHook returns a kms.KeyRotationHook that triggers a JWKS update
// on the target entity. It is a convenience wrapper around HTTPHook that reads
// the federation_jwks_update_trigger_endpoint,
// federation_jwks_update_trigger_endpoint_auth_methods and
// endpoint_auth_signing_alg_values_supported from the target's Entity
// Configuration, so the caller does not need to hardcode the endpoint URL,
// auth requirement, or algorithm list.
//
// At each invocation the hook checks whether the target requires
// private_key_jwt authentication and dispatches to the corresponding
// pre-built HTTPHook variant (with or without ClientAuth). All EC reads are
// served from the GetEntityConfiguration cache.
func TriggerUpdateHook(cfg TriggerUpdateHookConfig) (kms.KeyRotationHook, error) {
	if cfg.TargetEntityID == "" {
		return nil, errors.New("TriggerUpdateHook: TargetEntityID is required")
	}

	urlFunc := resolveEndpointFromEC(cfg.TargetEntityID, oidfedconst.FederationJWKSUpdateTriggerEndpoint, "jwks update trigger endpoint")

	withoutAuth, err := HTTPHook(
		HTTPHookConfig{
			URLFunc:  urlFunc,
			BodyMode: HTTPBodyEntityID,
			Headers:  cfg.Headers,
			Timeout:  cfg.Timeout,
		},
	)
	if err != nil {
		return nil, err
	}

	var withAuth kms.KeyRotationHook
	if cfg.ROProducer != nil {
		withAuth, err = HTTPHook(
			HTTPHookConfig{
				URLFunc:  urlFunc,
				BodyMode: HTTPBodyEntityID,
				Headers:  cfg.Headers,
				Timeout:  cfg.Timeout,
				ClientAuth: &HTTPHookClientAuth{
					ROProducer: cfg.ROProducer,
					Algs:       resolveAlgsFromEC(cfg.TargetEntityID),
				},
			},
		)
		if err != nil {
			return nil, err
		}
	}

	return func(ctx context.Context, event kms.KeyRotationEvent) error {
		required, aErr := triggerAuthRequiredFromEC(cfg.TargetEntityID)
		if aErr != nil {
			log.Logger().Error().Err(aErr).
				Str("target_entity_id", cfg.TargetEntityID).
				Str("entity_id", event.EntityID).
				Msg("key rotation trigger hook: could not determine auth requirement; falling back to no auth")
		}
		if required && withAuth != nil {
			return withAuth(ctx, event)
		}
		return withoutAuth(ctx, event)
	}, nil
}

// JWKSUpdateHookConfig configures a key rotation hook that POSTs a signed JWK
// Set (application/jwk-set+jwt) to the target entity's
// federation_jwks_update_endpoint, pushing the new federation keys. The
// endpoint URL is read dynamically from the target's Entity Configuration on
// each rotation (served from the EC cache). No client auth is used; the
// authenticity of the update is established by the signed JWK Set signature,
// which must verify against the entity's currently known federation keys.
type JWKSUpdateHookConfig struct {
	// TargetEntityID is the entity identifier of the federating entity (e.g.
	// a lighthouse) that exposes the jwks update endpoint.
	TargetEntityID string
	// Signer is the entity's federation signer used to mint the signed JWK Set
	// JWT. Required.
	Signer jwx.VersatileSigner
	// JWTLifetime is the lifetime (exp - iat) of the signed JWKS JWT.
	// Default: 10 minutes.
	JWTLifetime time.Duration
	// Headers are additional headers set on the request.
	Headers map[string]string
	// Timeout is the HTTP client timeout. Default: 20s.
	Timeout time.Duration
}

// JWKSUpdateHook returns a kms.KeyRotationHook that pushes a signed JWK Set to
// the target entity's federation_jwks_update_endpoint. It is a convenience
// wrapper around HTTPHook that reads the endpoint URL from the target's Entity
// Configuration, so the caller does not need to hardcode it.
func JWKSUpdateHook(cfg JWKSUpdateHookConfig) (kms.KeyRotationHook, error) {
	if cfg.TargetEntityID == "" {
		return nil, errors.New("JWKSUpdateHook: TargetEntityID is required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("JWKSUpdateHook: Signer is required")
	}
	return HTTPHook(
		HTTPHookConfig{
			URLFunc:     resolveEndpointFromEC(cfg.TargetEntityID, oidfedconst.FederationJWKSUpdateEndpoint, "jwks update endpoint"),
			BodyMode:    HTTPBodySignedJWKS,
			Signer:      cfg.Signer,
			JWTLifetime: cfg.JWTLifetime,
			Headers:     cfg.Headers,
			Timeout:     cfg.Timeout,
		},
	)
}
