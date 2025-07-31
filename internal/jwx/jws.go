package jwx

import (
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/go-oidfed/lib/jwx"
)

// ParsedJWT is a type extending jws.Message by holding the original jwt
type ParsedJWT struct {
	RawJWT []byte
	*jws.Message
}

// MarshalMsgpack implements the msgpack.Marshaler interface
func (p ParsedJWT) MarshalMsgpack() ([]byte, error) {
	return msgpack.Marshal(p.RawJWT)
}

// UnmarshalMsgpack implements the msgpack.Unmarshaler interface
func (p *ParsedJWT) UnmarshalMsgpack(data []byte) error {
	if err := msgpack.Unmarshal(data, &p.RawJWT); err != nil {
		return errors.WithStack(err)
	}
	pp, err := Parse(p.RawJWT)
	if err != nil {
		return err
	}
	*p = *pp
	return nil
}

// Parse parses a jwt and returns a ParsedJWT
func Parse(data []byte) (*ParsedJWT, error) {
	m, err := jws.Parse(data)
	return &ParsedJWT{
		RawJWT:  data,
		Message: m,
	}, errors.WithStack(err)
}

// VerifyWithSet uses a jwk.Set to verify a *jws.Message, returning the decoded payload or an error
func (p *ParsedJWT) VerifyWithSet(keys jwx.JWKS) ([]byte, error) {
	if p == nil || p.Message == nil {
		return nil, errors.New("jws.Verify: missing message")
	}
	if keys.Set == nil || keys.Len() == 0 {
		return nil, errors.New("jwt verify: no keys passed")
	}
	return jws.Verify(p.RawJWT, jws.WithKeySet(keys.Set, jws.WithInferAlgorithmFromKey(true)))
}

// VerifyType verifies that the header typ has a certain value
func (p *ParsedJWT) VerifyType(typ string) bool {
	if p.Signatures() == nil {
		return false
	}
	head := p.Signatures()[0].ProtectedHeaders()
	headerTyp, typSet := head.Type()
	return typSet && headerTyp == typ
}
