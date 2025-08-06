package oidfed

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unsafe"

	"github.com/pkg/errors"
)

// Metadata is a type for holding the different metadata types
type Metadata struct {
	OpenIDProvider           *OpenIDProviderMetadata           `json:"openid_provider,omitempty"`
	RelyingParty             *OpenIDRelyingPartyMetadata       `json:"openid_relying_party,omitempty"`
	OAuthAuthorizationServer *OAuthAuthorizationServerMetadata `json:"oauth_authorization_server,omitempty"`
	OAuthClient              *OAuthClientMetadata              `json:"oauth_client,omitempty"`
	OAuthProtectedResource   *OAuthProtectedResourceMetadata   `json:"oauth_resource,omitempty"`
	FederationEntity         *FederationEntityMetadata         `json:"federation_entity,omitempty"`
	// Extra contains additional metadata this entity should advertise.
	Extra map[string]any `json:"-"`
}

// DisplayNameGuesser is an interface for types to return a (guessed) display name
type DisplayNameGuesser interface {
	GuessDisplayName() string
}

// GuessEntityTypes returns a slice of entity types for which metadata is set
func (m Metadata) GuessEntityTypes() (entityTypes []string) {
	value := reflect.ValueOf(m)
	typ := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() == reflect.Ptr && !field.IsNil() {
			structField := typ.Field(i)
			jsonTag := structField.Tag.Get("json")
			jsonTag = strings.TrimSuffix(jsonTag, ",omitempty")
			entityTypes = append(entityTypes, jsonTag)
		}
	}
	return
}

// GuessDisplayName implements the DisplayNameGuesser interface
func (m OpenIDProviderMetadata) GuessDisplayName() string {
	if dn := m.DisplayName; dn != "" {
		return dn
	}
	return m.OrganizationName
}

// GuessDisplayName implements the DisplayNameGuesser interface
func (m OpenIDRelyingPartyMetadata) GuessDisplayName() string {
	if dn := m.DisplayName; dn != "" {
		return dn
	}
	return m.ClientName
}

// GuessDisplayName implements the DisplayNameGuesser interface
func (m OAuthAuthorizationServerMetadata) GuessDisplayName() string {
	if dn := m.DisplayName; dn != "" {
		return dn
	}
	return m.OrganizationName
}

// GuessDisplayName implements the DisplayNameGuesser interface
func (m OAuthClientMetadata) GuessDisplayName() string {
	if dn := m.DisplayName; dn != "" {
		return dn
	}
	return m.ClientName
}

// GuessDisplayName implements the DisplayNameGuesser interface
func (m OAuthProtectedResourceMetadata) GuessDisplayName() string {
	if dn := m.DisplayName; dn != "" {
		return dn
	}
	return m.ResourceName
}

// GuessDisplayName implements the DisplayNameGuesser interface
func (m FederationEntityMetadata) GuessDisplayName() string {
	if dn := m.DisplayName; dn != "" {
		return dn
	}
	return m.OrganizationName
}

// GuessDisplayNames collects (guessed) display names for all present metadata types.
func (m Metadata) GuessDisplayNames() map[string]string {
	result := make(map[string]string)
	value := reflect.ValueOf(m)
	typ := value.Type()

	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() == reflect.Ptr && !field.IsNil() {
			structField := typ.Field(i)
			entityTag := structField.Tag.Get("json")
			entityTag = strings.TrimSuffix(entityTag, ",omitempty")

			elem := field.Elem().Interface()
			displayNamer, ok := elem.(DisplayNameGuesser)
			if ok {
				result[entityTag] = displayNamer.GuessDisplayName()
			}
		}
	}
	return result
}

// IterateStringSliceClaim collects a claim that has a []string value for all
// metadata types and calls the iterator on it.
func (m Metadata) IterateStringSliceClaim(tag string, iterator func(entityType string, value []string)) {
	value := reflect.ValueOf(m)
	typ := value.Type()

	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() == reflect.Ptr && !field.IsNil() {
			structField := typ.Field(i)
			entityTag := structField.Tag.Get("json")
			entityTag = strings.TrimSuffix(entityTag, ",omitempty")

			elem := field.Elem()
			elemType := elem.Type()

			for j := 0; j < elem.NumField(); j++ {
				subField := elem.Field(j)
				subStructField := elemType.Field(j)
				jsonTag := subStructField.Tag.Get("json")
				jsonTag = strings.TrimSuffix(jsonTag, ",omitempty")

				if jsonTag == tag && subField.Kind() == reflect.String {
					slice := subField.Interface().([]string)
					if slice != nil {
						iterator(entityTag, slice)
					}
					break
				}
			}
		}
	}
}

// IterateStringClaim collects a claim that has a string value for all metadata
// types and calls the iterator on it.
func (m Metadata) IterateStringClaim(tag string, iterator func(entityType, value string)) {
	value := reflect.ValueOf(m)
	typ := value.Type()

	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() == reflect.Ptr && !field.IsNil() {
			structField := typ.Field(i)
			entityTag := structField.Tag.Get("json")
			entityTag = strings.TrimSuffix(entityTag, ",omitempty")

			elem := field.Elem()
			elemType := elem.Type()

			for j := 0; j < elem.NumField(); j++ {
				subField := elem.Field(j)
				subStructField := elemType.Field(j)
				jsonTag := subStructField.Tag.Get("json")
				jsonTag = strings.TrimSuffix(jsonTag, ",omitempty")

				if jsonTag == tag && subField.Kind() == reflect.String {
					str := subField.Interface().(string)
					if str != "" {
						iterator(entityTag, str)
					}
					break
				}
			}
		}
	}
}

// MarshalJSON implements the json.Marshaler interface.
// It also marshals extra fields.
func (m Metadata) MarshalJSON() ([]byte, error) {
	type metadata Metadata
	explicitFields, err := json.Marshal(metadata(m))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return extraMarshalHelper(explicitFields, m.Extra)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It also unmarshalls additional fields into the Extra claim.
func (m *Metadata) UnmarshalJSON(data []byte) error {
	type Alias Metadata
	mm := Alias(*m)
	extra, err := unmarshalWithExtra(data, &mm)
	if err != nil {
		return err
	}
	mm.Extra = extra
	*m = Metadata(mm)
	return nil
}

type policyApplicable interface {
	ApplyPolicy(policy MetadataPolicy) (any, error)
}

// ApplyPolicy applies MetadataPolicies to Metadata and returns the final Metadata
func (m Metadata) ApplyPolicy(p *MetadataPolicies) (*Metadata, error) {
	if p == nil {
		return &m, nil
	}
	t := reflect.TypeOf(m)
	v := reflect.ValueOf(m)
	out := &Metadata{}
	for i := 0; i < t.NumField(); i++ {
		// Ignore extra entities. We'll handle those separately without reflection.
		if t.Field(i).Name == "Extra" {
			continue
		}

		policy, policyOk := reflect.ValueOf(*p).Field(i).Interface().(MetadataPolicy)
		if !policyOk || policy == nil {
			reflect.Indirect(reflect.ValueOf(out)).Field(i).Set(v.Field(i))
			continue
		}
		var metadata policyApplicable
		f := v.Field(i)
		if f.IsNil() {
			continue
		}
		var ok bool
		metadata, ok = v.Field(i).Interface().(policyApplicable)
		if !ok {
			continue
		}
		applied, err := metadata.ApplyPolicy(policy)
		if err != nil {
			return nil, err
		}
		reflect.Indirect(reflect.ValueOf(out)).Field(i).Set(reflect.ValueOf(applied))
	}

	// Iterate over extra metadata and associated policies
	if len(m.Extra) > 0 {
		out.Extra = map[string]interface{}{}
		for entityType, metadata := range m.Extra {
			var metadataToReturn interface{}
			if policy, ok := p.Extra[entityType]; ok {
				// Found a policy for the entity type, so apply it
				applied, err := applyPolicy(metadata, policy, entityType)
				if err != nil {
					return nil, err
				}

				metadataToReturn = applied
			} else {
				// No policy found, so copy the metadata into out
				metadataToReturn = metadata
			}

			out.Extra[entityType] = metadataToReturn
		}
	}

	return out, nil
}

func applyPolicy(metadata any, policy MetadataPolicy, ownTag string) (any, error) {
	if policy == nil {
		return metadata, nil
	}
	v := reflect.ValueOf(metadata)
	t := v.Elem().Type()

	wasSetField := v.Elem().FieldByName("wasSet")
	wasSet := *(*map[string]bool)(unsafe.Pointer(wasSetField.UnsafeAddr())) // skipcq:  GSC-G103
	for i := 0; i < t.NumField(); i++ {
		j, ok := t.Field(i).Tag.Lookup("json")
		if !ok {
			continue
		}
		j = strings.TrimSuffix(j, ",omitempty")
		p, ok := policy[j]
		if !ok {
			continue
		}
		f := reflect.Indirect(v).Field(i)
		value, err := p.ApplyTo(f.Interface(), wasSet[t.Field(i).Name], fmt.Sprintf("%s.%s", ownTag, j))
		if err != nil {
			return nil, err
		}
		rV := reflect.ValueOf(value)
		if t.Field(i).Name == "Scope" && rV.IsValid() && rV.Kind() == reflect.Slice {
			strSlice, ok := value.([]string)
			if ok {
				rV = reflect.ValueOf(strings.Join(strSlice, " "))
			}
		}
		if rV.IsValid() {
			f.Set(rV)
		} else {
			f.SetZero()
		}
	}

	return metadata, nil
}

// FindEntityMetadata finds metadata for the specified entity type in the
// metadata and decodes it into the provided metadata object.
func (m *Metadata) FindEntityMetadata(entityType string, metadata any) error {
	// Validate that metadata is a pointer
	metadataValue := reflect.ValueOf(metadata)
	if metadataValue.Kind() != reflect.Ptr || metadataValue.IsNil() {
		return errors.New("metadata parameter must be a non-nil pointer")
	}

	// Check if the entity type indicates one of the explicit struct fields.
	v := reflect.ValueOf(m)
	t := v.Elem().Type()

	for i := 0; i < t.NumField(); i++ {
		j, ok := t.Field(i).Tag.Lookup("json")
		if !ok {
			continue
		}
		j = strings.TrimSuffix(j, ",omitempty")
		if j != entityType {
			continue
		}

		value := v.Elem().FieldByName(t.Field(i).Name)
		if value.IsZero() {
			continue
		}

		// Get the field value and set it to the metadata parameter
		fieldValue := value.Interface()
		sourceValue := reflect.ValueOf(fieldValue).Elem()

		// Create a new instance of the same type as the field
		targetValue := metadataValue.Elem()
		if !sourceValue.Type().AssignableTo(targetValue.Type()) {
			return errors.Errorf("cannot assign %v to %v", sourceValue.Type(), targetValue.Type())
		}

		targetValue.Set(sourceValue)
		return nil
	}

	// Requested entity type was not a struct field, so find it in the extra metadata.
	metadataMap, ok := m.Extra[entityType]
	if !ok {
		return errors.Errorf("could not find metadata for entity %s", entityType)
	}

	// Go will deserialize each metadata into a map[string]interface{}. There may be a nicer way to
	// do this with generics, but we encode that back to JSON, then decode it into the provided
	// struct so we can use RTTI to give the caller a richer representation.
	jsonMetadata, err := json.Marshal(metadataMap)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal metadata")
	}
	// Unmarshal the JSON data into the new instance
	if err = json.Unmarshal(jsonMetadata, metadata); err != nil {
		return errors.Wrapf(err, "failed to unmarshal metadata")
	}
	return nil
}

// OAuthClientMetadata is a type for holding the metadata about an oauth client
type OAuthClientMetadata OpenIDRelyingPartyMetadata
type oAuthClientMetadataWithPtrs openIDRelyingPartyMetadataWithPtrs

// OAuthAuthorizationServerMetadata is a type for holding the metadata about an oauth authorization server
type OAuthAuthorizationServerMetadata OpenIDProviderMetadata

// MarshalJSON implements the json.Marshaler interface
func (m OAuthAuthorizationServerMetadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(OpenIDProviderMetadata(m))
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (m *OAuthAuthorizationServerMetadata) UnmarshalJSON(data []byte) error {
	op := OpenIDProviderMetadata(*m)
	if err := json.Unmarshal(data, &op); err != nil {
		return err
	}
	*m = OAuthAuthorizationServerMetadata(op)
	return nil
}

type oAuthAuthorizationServerMetadataWithPtrs openIDProviderMetadataWithPtrs

// MarshalJSON implements the json.Marshaler interface
func (m oAuthAuthorizationServerMetadataWithPtrs) MarshalJSON() ([]byte, error) {
	return json.Marshal(openIDProviderMetadataWithPtrs(m))
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (m *oAuthAuthorizationServerMetadataWithPtrs) UnmarshalJSON(data []byte) error {
	op := openIDProviderMetadataWithPtrs(*m)
	if err := json.Unmarshal(data, &op); err != nil {
		return err
	}
	*m = oAuthAuthorizationServerMetadataWithPtrs(op)
	return nil
}

// ApplyPolicy applies a MetadataPolicy to the OAuthAuthorizationServerMetadata
func (m OAuthAuthorizationServerMetadata) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "oauth_authorization_server")
}

// MarshalJSON implements the json.Marshaler interface
func (m OAuthClientMetadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(OpenIDRelyingPartyMetadata(m))
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (m *OAuthClientMetadata) UnmarshalJSON(data []byte) error {
	rp := OpenIDRelyingPartyMetadata(*m)
	if err := json.Unmarshal(data, &rp); err != nil {
		return err
	}
	*m = OAuthClientMetadata(rp)
	return nil
}

// MarshalJSON implements the json.Marshaler interface
func (m oAuthClientMetadataWithPtrs) MarshalJSON() ([]byte, error) {
	return json.Marshal(openIDRelyingPartyMetadataWithPtrs(m))
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (m *oAuthClientMetadataWithPtrs) UnmarshalJSON(data []byte) error {
	rp := openIDRelyingPartyMetadataWithPtrs(*m)
	if err := json.Unmarshal(data, &rp); err != nil {
		return err
	}
	*m = oAuthClientMetadataWithPtrs(rp)
	return nil
}

// ApplyPolicy applies a MetadataPolicy to the OAuthClientMetadata
func (m OAuthClientMetadata) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "oauth_client")
}
