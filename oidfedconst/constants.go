package oidfedconst

// FederationSuffix is the well-known openid-federation suffix
const FederationSuffix = "/.well-known/openid-federation"

// Constants for JWT Types
const (
	ContentTypeEntityStatement              = "application/entity-statement+jwt"
	ContentTypeTrustMark                    = "application/trust-mark+jwt"
	ContentTypeResolveResponse              = "application/resolve-response+jwt"
	ContentTypeTrustChain                   = "application/trust-chain+json"
	ContentTypeTrustMarkDelegation          = "application/trust-mark-delegation+jwt"
	ContentTypeJWKS                         = "application/jwk-set+jwt"
	ContentTypeJWKSetJSON                   = "application/jwk-set+json"
	ContentTypeJSON                         = "application/json"
	ContentTypeForm                         = "application/x-www-form-urlencoded"
	ContentTypeExplicitRegistrationResponse = "application/explicit-registration-response+jwt"
	ContentTypeTrustMarkStatusResponse      = "application/trust-mark-status-response+jwt"
	JWTTypeEntityStatement                  = "entity-statement+jwt"
	JWTTypeTrustMarkDelegation              = "trust-mark-delegation+jwt"
	JWTTypeTrustMark                        = "trust-mark+jwt"
	JWTTypeResolveResponse                  = "resolve-response+jwt"
	JWTTypeJWKS                             = "jwk-set+jwt"
	JWTTypeExplicitRegistrationResponse     = "explicit-registration-response+jwt"
	JWTTypeTrustMarkStatusResponse          = "trust-mark-status-response+jwt"
)

// Constants for entity types
const (
	EntityTypeFederationEntity         = "federation_entity"
	EntityTypeOpenIDRelyingParty       = "openid_relying_party"
	EntityTypeOpenIDProvider           = "openid_provider"
	EntityTypeOAuthAuthorizationServer = "oauth_authorization_server"
	EntityTypeOAuthClient              = "oauth_client"
	EntityTypeOAuthProtectedResource   = "oauth_resource"
)

// Constants for registration types
const (
	ClientRegistrationTypeAutomatic = "automatic"
	ClientRegistrationTypeExplicit  = "explicit"
)

// Constants for auth methods
const (
	AuthMethodPrivateKeyJWT = "private_key_jwt"
)

// Constants for OAuth client assertion types
const (
	OAuthClientAssertionJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// Constants for federation_entity metadata Extra keys. These endpoints are
// published in the FederationEntityMetadata.Extra map by federating entities
// such as a lighthouse; they are not part of the core metadata struct.
const (
	// FederationJWKSUpdateEndpoint is the Extra key for the
	// federation_jwks_update_endpoint. A subordinate POSTs a signed JWK Set
	// (application/jwk-set+jwt, typ jwk-set+jwt) to this endpoint to push new
	// federation keys. No private_key_jwt client auth is used; authenticity is
	// established by the signed JWK Set signature.
	FederationJWKSUpdateEndpoint = "federation_jwks_update_endpoint"
	// FederationJWKSUpdateTriggerEndpoint is the Extra key for the
	// federation_jwks_update_trigger_endpoint. A POST tells the federating
	// entity to re-fetch the subordinate's JWKS from its Entity Configuration
	// and update the stored keys if they changed. May use private_key_jwt
	// client authentication.
	FederationJWKSUpdateTriggerEndpoint = "federation_jwks_update_trigger_endpoint"
	// FederationJWKSUpdateTriggerEndpointAuthMethods is the Extra key for the
	// auth methods supported by the trigger endpoint.
	FederationJWKSUpdateTriggerEndpointAuthMethods = "federation_jwks_update_trigger_endpoint_auth_methods"
)
