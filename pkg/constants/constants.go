package constants

// Constants for JWT Types
const (
	ContentTypeEntityStatement              = "application/entity-statement+jwt"
	ContentTypeTrustMark                    = "application/trust-mark+jwt"
	ContentTypeResolveResponse              = "application/resolve-response+jwt"
	ContentTypeTrustChain                   = "application/trust-chain+json"
	ContentTypeTrustMarkDelegation          = "application/trust-mark-delegation+jwt"
	ContentTypeJWKS                         = "application/jwk-set+jwt"
	ContentTypeExplicitRegistrationResponse = "application/explicit-registration-response+jwt"
	JWTTypeEntityStatement                  = "entity-statement+jwt"
	JWTTypeTrustMarkDelegation              = "trust-mark-delegation+jwt"
	JWTTypeTrustMark                        = "trust-mark+jwt"
	JWTTypeResolveResponse                  = "resolve-response+jwt"
	JWTTypeJWKS                             = "jwk-set+jwt"
	JWTTypeExplicitRegistrationResponse     = "explicit-registration-response+jwt"
)

// Constants for entity types
const (
	EntityTypeFederationEntity       = "federation_entity"
	EntityTypeOpenIDRelyingParty     = "openid_relying_party"
	EntityTypeOpenIDProvider         = "openid_provider"
	EntityTypeOAuthClient            = "oauth_client"
	EntityTypeOAuthProtectedResource = "oauth_resource"
)
