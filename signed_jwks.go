package oidfed

import (
	"encoding/json"

	"github.com/pkg/errors"

	jwxi "github.com/go-oidfed/lib/internal/jwx"
	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/go-oidfed/lib/unixtime"
)

// SignedJWKS holds a parsed signed JWK Set JWT (media type
// application/jwk-set+jwt, typ jwk-set+jwt) as defined in section 5.2.1 of the
// OpenID Federation 1.0 specification. It is the payload format used by the
// signed_jwks_uri metadata parameter
type SignedJWKS struct {
	jwtMsg *jwxi.ParsedJWT
	// Keys is the REQUIRED "keys" claim: the array of JWK values.
	Keys jwx.JWKS `json:"keys"`
	// Issuer is the REQUIRED "iss" claim.
	Issuer string `json:"iss"`
	// Subject is the REQUIRED "sub" claim (owner of the keys; SHOULD equal iss).
	Subject string `json:"sub"`
	// IssuedAt is the OPTIONAL "iat" claim.
	IssuedAt *unixtime.Unixtime `json:"iat,omitempty"`
	// ExpiresAt is the OPTIONAL "exp" claim.
	ExpiresAt *unixtime.Unixtime `json:"exp,omitempty"`
}

// Verify verifies the signed JWK Set JWT signature against the provided JWKS.
func (s SignedJWKS) Verify(keys jwx.JWKS) bool {
	if s.jwtMsg == nil {
		return false
	}
	_, err := s.jwtMsg.VerifyWithSet(keys)
	return err == nil
}

// KID returns the kid header of the signing key, if present.
func (s SignedJWKS) KID() (string, bool) {
	if s.jwtMsg == nil || s.jwtMsg.Signatures() == nil || len(s.jwtMsg.Signatures()) == 0 {
		return "", false
	}
	return s.jwtMsg.Signatures()[0].ProtectedHeaders().KeyID()
}

// signedJWKSPayload is the raw payload structure used for unmarshaling.
type signedJWKSPayload struct {
	Keys      jwx.JWKS           `json:"keys"`
	Issuer    string             `json:"iss"`
	Subject   string             `json:"sub"`
	IssuedAt  *unixtime.Unixtime `json:"iat,omitempty"`
	ExpiresAt *unixtime.Unixtime `json:"exp,omitempty"`
	Extra     map[string]any     `json:"-"`
}

// ParseSignedJWKS parses a signed JWK Set JWT (application/jwk-set+jwt) and
// validates the structural requirements from section 5.2.1:
//   - the JWT typ header MUST be "jwk-set+jwt";
//   - the kid header MUST be present;
//   - the "keys" claim is REQUIRED and MUST be a non-empty array of JWKs with
//     unique, non-empty kids;
//   - the "iss" and "sub" claims are REQUIRED.
//
// Signature verification is NOT performed by Parse; call Verify with the
// expected JWKS afterwards.
func ParseSignedJWKS(jwtBytes []byte) (*SignedJWKS, error) {
	m, err := jwxi.Parse(jwtBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse signed JWK Set JWT")
	}
	if !m.VerifyType(oidfedconst.JWTTypeJWKS) {
		return nil, errors.Errorf(
			"signed JWK Set does not have '%s' JWT type", oidfedconst.JWTTypeJWKS,
		)
	}
	// kid header is REQUIRED.
	if m.Signatures() == nil || len(m.Signatures()) == 0 {
		return nil, errors.New("signed JWK Set has no signatures")
	}
	kid, kidSet := m.Signatures()[0].ProtectedHeaders().KeyID()
	if !kidSet || kid == "" {
		return nil, errors.New("signed JWK Set is missing the required 'kid' header")
	}

	var payload signedJWKSPayload
	if err = json.Unmarshal(m.Payload(), &payload); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal signed JWK Set payload")
	}
	if payload.Issuer == "" {
		return nil, errors.New("signed JWK Set is missing the required 'iss' claim")
	}
	if payload.Subject == "" {
		return nil, errors.New("signed JWK Set is missing the required 'sub' claim")
	}
	if payload.Keys.Set == nil || payload.Keys.Len() == 0 {
		return nil, errors.New("signed JWK Set is missing the required 'keys' claim")
	}
	// Every key MUST have a unique, non-empty kid.
	seen := make(map[string]struct{}, payload.Keys.Len())
	for _, k := range payload.Keys.All() {
		kid, ok := k.KeyID()
		if !ok || kid == "" {
			return nil, errors.New("every key in the signed JWK Set MUST have a non-empty kid")
		}
		if _, dup := seen[kid]; dup {
			return nil, errors.Errorf("duplicate kid in signed JWK Set: %s", kid)
		}
		seen[kid] = struct{}{}
	}

	return &SignedJWKS{
		jwtMsg:    m,
		Keys:      payload.Keys,
		Issuer:    payload.Issuer,
		Subject:   payload.Subject,
		IssuedAt:  payload.IssuedAt,
		ExpiresAt: payload.ExpiresAt,
	}, nil
}
