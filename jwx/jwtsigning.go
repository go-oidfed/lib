package jwx

import (
	"crypto"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/oidfedconst"
)

// VersatileSigner is an interface type for obtaining a crypto.Signer for a specific jwa.
// SignatureAlgorithm and the corresponding (full) jwks.JWKS
// The purpose of this interface is to enable:
// (1) easy usage of signing with potentially multiple algs,
// e.g. in oidc the public_key_jwt client auth method might use one alg with one OP and another alg with another OP;
// this requires different crypto.Signer but we still want to easily access a single combined jwks.JWKS
// (2) key rotation; by using a function to obtain the crypto.Signer it is possible that the used crypto.
// Signer changes over time
type VersatileSigner interface {
	// Signer takes a list of acceptable signature algorithms and returns a
	// usable crypto.Signer or nil as well as the corresponding
	// jwa.SignatureAlgorithm
	Signer(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm)
	// DefaultSigner returns a crypto.Signer and the corresponding jwa.SignatureAlgorithm
	DefaultSigner() (crypto.Signer, jwa.SignatureAlgorithm)
	// JWKS returns the jwks.JWKS containing all public keys of this VersatileSigner
	JWKS() (JWKS, error)
}

// JWTSigner is an interface that can give signed jwts
type JWTSigner interface {
	JWT(i any, alg ...jwa.SignatureAlgorithm) (jwt []byte, err error)
	JWKS() (JWKS, error)
}

// GeneralJWTSigner is a general jwt signer with no specific typ
type GeneralJWTSigner struct {
	signer VersatileSigner
	algs   []jwa.SignatureAlgorithm
}

// NewGeneralJWTSigner creates a new GeneralJWTSigner using the passed VersatileSigner.
// The passed algorithms define which algorithms can be used; the order also implies a preference,
// where the first alg is the preferred signing algorithm.
func NewGeneralJWTSigner(
	signer VersatileSigner, algs []jwa.SignatureAlgorithm,
) *GeneralJWTSigner {
	return &GeneralJWTSigner{
		signer: signer,
		algs:   algs,
	}
}

// JWT returns a signed jwt representation of the passed data with the passed header type
func (s GeneralJWTSigner) JWT(i any, headerType string, algs ...string) (jwt []byte, err error) {
	var signer crypto.Signer
	var alg jwa.SignatureAlgorithm
	if len(algs) == 0 {
		signer, alg = s.signer.DefaultSigner()
	} else {
		signer, alg = s.signer.Signer(algs...)
	}
	if signer == nil {
		return nil, errors.New("no compatible signing key found")
	}
	var j []byte
	j, err = json.Marshal(i)
	if err != nil {
		return
	}
	jwt, err = SignWithType(j, headerType, alg, signer)
	return
}

// JWKS returns the jwks.JWKS used with this signer
func (s *GeneralJWTSigner) JWKS() (JWKS, error) {
	return s.signer.JWKS()
}

// Typed returns a TypedJWTSigner for the passed header type using the same crypto.Signer
func (s *GeneralJWTSigner) Typed(headerType string) *TypedJWTSigner {
	return &TypedJWTSigner{
		GeneralJWTSigner: s,
		HeaderType:       headerType,
	}
}

// EntityStatementSigner returns an EntityStatementSigner using the same crypto.Signer
func (s *GeneralJWTSigner) EntityStatementSigner() *EntityStatementSigner {
	return &EntityStatementSigner{s}
}

// TrustMarkSigner returns an TrustMarkSigner using the same crypto.Signer
func (s *GeneralJWTSigner) TrustMarkSigner() *TrustMarkSigner {
	return &TrustMarkSigner{s}
}

// TrustMarkDelegationSigner returns an TrustMarkDelegationSigner using the same
// crypto.Signer
func (s *GeneralJWTSigner) TrustMarkDelegationSigner() *TrustMarkDelegationSigner {
	return &TrustMarkDelegationSigner{s}
}

// ResolveResponseSigner returns an ResolveResponseSigner using the same crypto.Signer
func (s *GeneralJWTSigner) ResolveResponseSigner() *ResolveResponseSigner {
	return &ResolveResponseSigner{s}
}

// ResolveResponseSigner is a JWTSigner for oidfedconst.JWTTypeResolveResponse
type ResolveResponseSigner struct {
	*GeneralJWTSigner
}

// TrustMarkDelegationSigner is a JWTSigner for constants.
// JWTTypeTrustMarkDelegation
type TrustMarkDelegationSigner struct {
	*GeneralJWTSigner
}

// TrustMarkSigner is a JWTSigner for oidfedconst.JWTTypeTrustMark
type TrustMarkSigner struct {
	*GeneralJWTSigner
}

// EntityStatementSigner is a JWTSigner for oidfedconst.JWTTypeEntityStatement
type EntityStatementSigner struct {
	*GeneralJWTSigner
}

// JWT implements the JWTSigner interface
func (s ResolveResponseSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, oidfedconst.JWTTypeResolveResponse)
}

// JWT implements the JWTSigner interface
func (s TrustMarkDelegationSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, oidfedconst.JWTTypeTrustMarkDelegation)
}

// JWT implements the JWTSigner interface
func (s TrustMarkSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, oidfedconst.JWTTypeTrustMark)
}

// JWT implements the JWTSigner interface
func (s EntityStatementSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, oidfedconst.JWTTypeEntityStatement)
}

// NewEntityStatementSigner creates a new EntityStatementSigner
func NewEntityStatementSigner(signer VersatileSigner) *EntityStatementSigner {
	_, alg := signer.DefaultSigner()
	return &EntityStatementSigner{
		GeneralJWTSigner: NewGeneralJWTSigner(signer, []jwa.SignatureAlgorithm{alg}),
	}
}

// NewResolveResponseSigner creates a new ResolveResponseSigner
func NewResolveResponseSigner(signer VersatileSigner) *ResolveResponseSigner {
	_, alg := signer.DefaultSigner()
	return &ResolveResponseSigner{
		GeneralJWTSigner: NewGeneralJWTSigner(signer, []jwa.SignatureAlgorithm{alg}),
	}
}

// NewTrustMarkSigner creates a new TrustMarkSigner
func NewTrustMarkSigner(signer VersatileSigner) *TrustMarkSigner {
	_, alg := signer.DefaultSigner()
	return &TrustMarkSigner{
		GeneralJWTSigner: NewGeneralJWTSigner(signer, []jwa.SignatureAlgorithm{alg}),
	}
}

// NewTrustMarkDelegationSigner creates a new TrustMarkDelegationSigner
func NewTrustMarkDelegationSigner(signer VersatileSigner) *TrustMarkDelegationSigner {
	_, alg := signer.DefaultSigner()
	return &TrustMarkDelegationSigner{
		GeneralJWTSigner: NewGeneralJWTSigner(signer, []jwa.SignatureAlgorithm{alg}),
	}
}

// TypedJWTSigner is a JWTSigner for a specific header type
type TypedJWTSigner struct {
	*GeneralJWTSigner
	HeaderType string
}

// JWT implements the JWTSigner interface
func (s TypedJWTSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, s.HeaderType)
}

// SignWithType creates a signed JWT of the passed type for the passed payload using the
// passed crypto.Signer with the passed jwa.SignatureAlgorithm
func SignWithType(payload []byte, typ string, signingAlg jwa.SignatureAlgorithm, key crypto.Signer) ([]byte, error) {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, typ); err != nil {
		return nil, err
	}
	return SignPayload(payload, signingAlg, key, headers)
}

// SignPayload signs a payload with the passed properties and adds the kid to the jwt header
func SignPayload(payload []byte, signingAlg jwa.SignatureAlgorithm, key crypto.Signer, headers jws.Headers) (
	[]byte,
	error,
) {
	type signerWithKID interface{ KID() string }
	var keyID string
	if s, ok := key.(signerWithKID); ok {
		keyID = s.KID()
	} else {
		k, err := jwk.PublicKeyOf(key.Public())
		if err != nil {
			return nil, err
		}
		if err = jwk.AssignKeyID(k); err != nil {
			return nil, err
		}
		keyID, _ = k.KeyID()
	}
	if headers == nil {
		headers = jws.NewHeaders()
	}
	if err := headers.Set(jws.KeyIDKey, keyID); err != nil {
		return nil, err
	}
	return jws.Sign(payload, jws.WithKey(signingAlg, key, jws.WithProtectedHeaders(headers)))
}
