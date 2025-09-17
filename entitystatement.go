package oidfed

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/zachmann/go-utils/structutils"
	"gopkg.in/yaml.v3"

	"github.com/go-oidfed/lib/internal"
	jwxi "github.com/go-oidfed/lib/internal/jwx"
	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/oidfedconst"
	"github.com/go-oidfed/lib/unixtime"
)

const defaultEntityConfigurationLifetime = time.Hour * 24 // 1d

// EntityStatement is a type for holding an entity statement, more precisely an entity statement that was obtained
// as a jwt and created by us
type EntityStatement struct {
	jwtMsg *jwxi.ParsedJWT
	EntityStatementPayload
}

// Verify verifies that the EntityStatement jwt is valid
func (e EntityStatement) Verify(keys jwx.JWKS) bool {
	_, err := e.jwtMsg.VerifyWithSet(keys)
	if err != nil {
		internal.Log(err)
	}
	return err == nil
}

type entityStatementExported struct {
	Payload EntityStatementPayload
	JWTMsg  jwxi.ParsedJWT
}

// MarshalMsgpack implements the msgpack.Marshaler interface for usage with caching
func (e EntityStatement) MarshalMsgpack() ([]byte, error) {
	ee := entityStatementExported{
		Payload: e.EntityStatementPayload,
	}
	if e.jwtMsg != nil {
		ee.JWTMsg = *e.jwtMsg
	}
	data, err := msgpack.Marshal(ee)
	return data, err
}

// UnmarshalMsgpack implements the msgpack.Unmarshaler interface for usage with caching
func (e *EntityStatement) UnmarshalMsgpack(data []byte) error {
	var ee entityStatementExported
	if err := msgpack.Unmarshal(data, &ee); err != nil {
		return err
	}
	e.EntityStatementPayload = ee.Payload
	e.jwtMsg = &ee.JWTMsg
	return nil
}

// EntityStatementPayload is a type for holding the actual payload of an EntityStatement or EntityConfiguration;
// additional fields can be set in the Extra claim
type EntityStatementPayload struct {
	Issuer             string                   `json:"iss"`
	Subject            string                   `json:"sub"`
	IssuedAt           unixtime.Unixtime        `json:"iat"`
	ExpiresAt          unixtime.Unixtime        `json:"exp"`
	JWKS               jwx.JWKS                 `json:"jwks"`
	Audience           string                   `json:"aud,omitempty"`
	AuthorityHints     []string                 `json:"authority_hints,omitempty"`
	Metadata           *Metadata                `json:"metadata,omitempty"`
	MetadataPolicy     *MetadataPolicies        `json:"metadata_policy,omitempty"`
	Constraints        *ConstraintSpecification `json:"constraints,omitempty"`
	CriticalExtensions []string                 `json:"crit,omitempty"`
	MetadataPolicyCrit []PolicyOperatorName     `json:"metadata_policy_crit,omitempty"`
	TrustMarks         TrustMarkInfos           `json:"trust_marks,omitempty"`
	TrustMarkIssuers   AllowedTrustMarkIssuers  `json:"trust_mark_issuers,omitempty"`
	TrustMarkOwners    TrustMarkOwners          `json:"trust_mark_owners,omitempty"`
	SourceEndpoint     string                   `json:"source_endpoint,omitempty"`
	TrustAnchor        string                   `json:"trust_anchor,omitempty"`
	Extra              map[string]interface{}   `json:"-"`
}

// TimeValid checks if the EntityStatementPayload is already valid and not yet expired.
func (e EntityStatementPayload) TimeValid() bool {
	return unixtime.VerifyTime(&e.IssuedAt, &e.ExpiresAt) == nil
}

func extraMarshalHelper(explicitFields []byte, extra map[string]interface{}) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(explicitFields, &m); err != nil {
		return nil, err
	}
	for k, v := range extra {
		e, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		m[k] = e
	}
	data, err := json.Marshal(m)
	return data, errors.WithStack(err)
}

func yamlExtraMarshalHelper(explicitFields []byte, extra map[string]interface{}) (any, error) {
	var m map[string]*yaml.Node
	if err := yaml.Unmarshal(explicitFields, &m); err != nil {
		return nil, err
	}
	for k, v := range extra {
		node := &yaml.Node{}
		if err := node.Encode(v); err != nil {
			return nil, errors.WithStack(err)
		}
		m[k] = node
	}
	return m, nil
}

// MarshalJSON implements the json.Marshaler interface.
// It also marshals extra fields.
func (e EntityStatementPayload) MarshalJSON() ([]byte, error) {
	type entityStatement EntityStatementPayload
	explicitFields, err := json.Marshal(entityStatement(e))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return extraMarshalHelper(explicitFields, e.Extra)
}

func unmarshalWithExtra(data []byte, target interface{}) (map[string]interface{}, error) {
	if err := json.Unmarshal(data, target); err != nil {
		return nil, errors.WithStack(err)
	}
	extra := make(map[string]interface{})
	if err := json.Unmarshal(data, &extra); err != nil {
		return nil, errors.WithStack(err)
	}
	for _, tag := range structutils.FieldTagNames(target, "json") {
		delete(extra, tag)
	}
	if len(extra) == 0 {
		extra = nil
	}
	return extra, nil
}

func yamlUnmarshalWithExtra(data *yaml.Node, target interface{}) (map[string]interface{}, error) {
	if err := data.Decode(target); err != nil {
		return nil, errors.WithStack(err)
	}
	extra := make(map[string]interface{})
	if err := data.Decode(&extra); err != nil {
		return nil, errors.WithStack(err)
	}
	for _, tag := range structutils.FieldTagNames(target, "yaml") {
		delete(extra, tag)
	}
	if len(extra) == 0 {
		extra = nil
	}
	return extra, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It also unmarshalls additional fields into the Extra claim.
func (e *EntityStatementPayload) UnmarshalJSON(data []byte) error {
	type Alias EntityStatementPayload
	ee := Alias(*e)
	extra, err := unmarshalWithExtra(data, &ee)
	if err != nil {
		return err
	}
	ee.Extra = extra
	*e = EntityStatementPayload(ee)
	return nil
}

// UnmarshalMsgpack implements the msgpack.Unmarshaler interface.
func (e *EntityStatementPayload) UnmarshalMsgpack(data []byte) error {
	type entityStatement EntityStatementPayload
	ee := entityStatement(*e)
	if err := msgpack.Unmarshal(data, &ee); err != nil {
		return err
	}
	*e = EntityStatementPayload(ee)
	return nil
}

// ConstraintSpecification is type for holding constraints according to the oidc fed spec
type ConstraintSpecification struct {
	MaxPathLength      *int               `json:"max_path_length,omitempty"`
	NamingConstraints  *NamingConstraints `json:"naming_constraints,omitempty"`
	AllowedEntityTypes []string           `json:"allowed_entity_types,omitempty"`
}

// NamingConstraints is a type for holding constraints about naming
type NamingConstraints struct {
	Permitted []string `json:"permitted,omitempty"`
	Excluded  []string `json:"excluded,omitempty"`
}

// AllowedTrustMarkIssuers is type for defining which TrustMark can be issued by which entities
type AllowedTrustMarkIssuers map[string][]string

// TrustMarkOwners defines owners for TrustMarks
type TrustMarkOwners map[string]TrustMarkOwnerSpec

// TrustMarkOwnerSpec describes the owner of a trust mark
type TrustMarkOwnerSpec struct {
	ID   string   `json:"sub" yaml:"entity_id"`
	JWKS jwx.JWKS `json:"jwks" yaml:"jwks"`
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (tmo *TrustMarkOwnerSpec) UnmarshalJSON(data []byte) error {
	type trustMarkOwner TrustMarkOwnerSpec
	o := trustMarkOwner(*tmo)
	if err := json.Unmarshal(data, &o); err != nil {
		return err
	}
	*tmo = TrustMarkOwnerSpec(o)
	return nil
}

// UnmarshalMsgpack implements the msgpack.Unmarshaler interface.
func (tmo *TrustMarkOwnerSpec) UnmarshalMsgpack(data []byte) error {
	type trustMarkOwner TrustMarkOwnerSpec
	o := trustMarkOwner(*tmo)
	if err := msgpack.Unmarshal(data, &o); err != nil {
		return err
	}
	*tmo = TrustMarkOwnerSpec(o)
	return nil
}

// ParseEntityStatement parses a jwt into an EntityStatement
func ParseEntityStatement(statementJWT []byte) (*EntityStatement, error) {
	m, err := jwxi.Parse(statementJWT)
	if err != nil {
		return nil, err
	}
	if !m.VerifyType(oidfedconst.JWTTypeEntityStatement) {
		return nil, errors.Errorf("entity statement does not have '%s' JWT type", oidfedconst.JWTTypeEntityStatement)
	}
	statement := &EntityStatement{
		jwtMsg:                 m,
		EntityStatementPayload: EntityStatementPayload{},
	}
	if err = json.Unmarshal(m.Payload(), &statement.EntityStatementPayload); err != nil {
		return nil, err
	}
	return statement, err
}
