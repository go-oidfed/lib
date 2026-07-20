package jwx

import (
	"bytes"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/pkg/errors"
	"github.com/scylladb/go-set/strset"
	"github.com/vmihailenco/msgpack/v5"
	"gopkg.in/yaml.v3"

	"github.com/go-oidfed/lib/unixtime"
)

func init() {
	for _, field := range []string{"exp", "iat", "nbf"} {
		if err := jwk.RegisterCustomField[unixtime.Unixtime](field); err != nil {
			panic(err)
		}
	}
}

// JWKS is a wrapper type for jwk.Set to implement custom marshaling
type JWKS struct {
	jwk.Set
}

// NewJWKS returns a new JWKS
func NewJWKS() JWKS {
	return JWKS{jwk.NewSet()}
}

// MarshalJSON implements the json.Marshaler interface
func (jwks JWKS) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(jwks.Set)
	return data, errors.WithStack(err)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (jwks *JWKS) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		jwks.Set = nil
		return nil
	}
	if jwks.Set == nil {
		jwks.Set = jwk.NewSet()
	}
	if err := json.Unmarshal(data, jwks.Set); err != nil {
		return errors.WithStack(err)
	}
	if jwks.Len() == 0 {
		jwks.Set = nil
	}
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (jwks JWKS) MarshalYAML() (any, error) {
	data, err := json.Marshal(jwks.Set)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var generic any
	if err = json.Unmarshal(data, &generic); err != nil {
		return nil, errors.WithStack(err)
	}
	return generic, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface
func (jwks *JWKS) UnmarshalYAML(node *yaml.Node) error {
	var generic map[string]interface{}
	if err := node.Decode(&generic); err != nil {
		return errors.WithStack(err)
	}
	genericJSON, err := json.Marshal(generic)
	if err != nil {
		return errors.WithStack(err)
	}
	return jwks.UnmarshalJSON(genericJSON)
}

// MarshalMsgpack implements the msgpack.Marshaler interface
func (jwks JWKS) MarshalMsgpack() ([]byte, error) {
	data, err := json.Marshal(jwks)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	msgpackData, err := msgpack.Marshal(data)
	return msgpackData, errors.WithStack(err)
}

// UnmarshalMsgpack implements the msgpack.Unmarshaler interface
func (jwks *JWKS) UnmarshalMsgpack(data []byte) error {
	var jsonData []byte
	if err := msgpack.Unmarshal(data, &jsonData); err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(json.Unmarshal(jsonData, jwks))
}

// MinimalExpirationTime iterates over all keys in the JWKS if they have an exp claim set and returns the minimal
// expiration time of all keys
func (jwks JWKS) MinimalExpirationTime() unixtime.Unixtime {
	var exp unixtime.Unixtime
	for _, k := range jwks.All() {
		e, err := jwk.Get[unixtime.Unixtime](k, "exp")
		if err != nil {
			continue
		}
		if exp.IsZero() || e.Before(exp.Time) {
			exp = e
		}
	}
	return exp
}

// MaximalExpirationTime iterates over all keys in the JWKS if they have an exp claim set and returns the maximal
// expiration time of all keys.
func (jwks JWKS) MaximalExpirationTime() unixtime.Unixtime {
	var exp unixtime.Unixtime
	for _, k := range jwks.All() {
		e, err := jwk.Get[unixtime.Unixtime](k, "exp")
		if err != nil {
			continue
		}
		if exp.IsZero() || e.After(exp.Time) {
			exp = e
		}
	}
	return exp
}

// MergeJWKS merges two JWKS into a new one, deduplicating by KID.
// Keys from primary take priority on KID conflicts (i.e. if the same KID
// appears in both, the primary's key is kept).
// Keys without a KID are all kept from both sets.
func MergeJWKS(primary, secondary JWKS) JWKS {
	merged := jwk.NewSet()
	seenKIDs := strset.New()

	if primary.Set != nil {
		for _, key := range primary.All() {
			if kid, ok := key.KeyID(); ok && kid != "" {
				seenKIDs.Add(kid)
			}
			_ = merged.AddKey(key)
		}
	}

	if secondary.Set != nil {
		for _, key := range secondary.All() {
			if kid, ok := key.KeyID(); ok && kid != "" {
				if seenKIDs.Has(kid) {
					continue
				}
			}
			_ = merged.AddKey(key)
		}
	}

	return JWKS{merged}
}

var zeroJWKS JWKS

// KeyToJWKS creates a jwk.Set from the passed publicKey and sets the algorithm key in the jwk.Key to the passed jwa.SignatureAlgorithm
func KeyToJWKS(publicKey interface{}, alg jwa.SignatureAlgorithm) (JWKS, error) {
	key, err := jwk.PublicKeyOf(publicKey)
	if err != nil {
		return zeroJWKS, err
	}
	if err = jwk.AssignKeyID(key); err != nil {
		return zeroJWKS, errors.WithStack(err)
	}
	if err = key.Set(jwk.KeyUsageKey, string(jwk.ForSignature)); err != nil {
		return zeroJWKS, errors.WithStack(err)
	}
	if err = key.Set(jwk.AlgorithmKey, alg); err != nil {
		return zeroJWKS, errors.WithStack(err)
	}
	jwks := jwk.NewSet()
	err = errors.WithStack(jwks.AddKey(key))
	return JWKS{jwks}, err
}
