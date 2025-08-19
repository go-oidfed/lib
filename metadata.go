package oidfed

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
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

// ApplyInformationalClaimsToFederationEntity copies common informational claims from other
// entity types to the federation entity metadata if they have consistent values and are not already set on the
// federation entity metadata.
// It processes both string claims (like organization_name, policy_uri etc.) and string slice
// claims (like contacts).
// The method only copies a claim if:
// - The value is consistent across all entity types that have it set
// - The federation entity doesn't already have a value for that claim
// If the federation entity metadata doesn't exist, it will be created when needed.
func (m *Metadata) ApplyInformationalClaimsToFederationEntity() {
	// Define informational claims by type
	stringClaims := []string{
		"organization_name",
		"policy_uri",
		"tos_uri",
		"logo_uri",
		"client_uri",
	}
	stringSliceClaims := []string{
		"contacts",
	}

	// Process string claims
	stringClaimsToCopy := m.collectConsistentStringClaims(stringClaims)

	// Process string slice claims
	stringSliceClaimsToCopy := m.collectConsistentStringSliceClaims(stringSliceClaims)

	// Apply the collected claims to federation entity if needed
	if len(stringClaimsToCopy) > 0 || len(stringSliceClaimsToCopy) > 0 {
		if m.FederationEntity == nil {
			m.FederationEntity = &FederationEntityMetadata{}
		}

		// Apply string claims
		if len(stringClaimsToCopy) > 0 {
			m.applyStringClaimsToFederationEntity(stringClaimsToCopy)
		}

		// Apply string slice claims
		if len(stringSliceClaimsToCopy) > 0 {
			m.applyStringSliceClaimsToFederationEntity(stringSliceClaimsToCopy)
		}
	}
}

// collectConsistentStringClaims gathers string claims that have consistent values across entity types
// and aren't yet set on the federation entity.
func (m *Metadata) collectConsistentStringClaims(claims []string) map[string]string {
	result := make(map[string]string)

	for _, claim := range claims {
		var commonValue string
		var hasConflict bool

		m.IterateStringClaim(
			claim, func(entityType, value string) {
				if entityType == "federation_entity" {
					if value != "" {
						hasConflict = true // if federation_entity already has the value set, to not overwrite it
					}
					return
				}
				if value == "" {
					return
				}
				if commonValue == "" {
					commonValue = value
					return
				}
				if value != commonValue {
					hasConflict = true
				}
			},
		)

		if !hasConflict && commonValue != "" {
			result[claim] = commonValue
		}
	}

	return result
}

// collectConsistentStringSliceClaims gathers string slice claims that have consistent values across entity types
// and aren't yet set on the federation entity.
func (m *Metadata) collectConsistentStringSliceClaims(claims []string) map[string][]string {
	result := make(map[string][]string)

	for _, claim := range claims {
		var commonValue []string
		var hasConflict bool

		m.IterateStringSliceClaim(
			claim, func(entityType string, value []string) {
				if entityType == "federation_entity" {
					if value != nil {
						hasConflict = true // if federation_entity already has the value set, to not overwrite it
					}
					return
				}
				if value == nil {
					return
				}
				if commonValue == nil {
					commonValue = value
					return
				}
				if !slices.Equal(value, commonValue) {
					hasConflict = true
				}
			},
		)

		if !hasConflict && commonValue != nil {
			result[claim] = commonValue
		}
	}

	return result
}

// applyStringClaimsToFederationEntity applies the given string claims to the federation entity using reflection.
func (m *Metadata) applyStringClaimsToFederationEntity(claims map[string]string) {
	v := reflect.ValueOf(m.FederationEntity).Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.Type.Kind() != reflect.String {
			continue
		}
		tag, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		value, found := claims[tag]
		if found {
			v.Field(i).SetString(value)
		}
	}
}

// applyStringSliceClaimsToFederationEntity applies the given string slice claims to the federation entity using reflection.
func (m *Metadata) applyStringSliceClaimsToFederationEntity(claims map[string][]string) {
	v := reflect.ValueOf(m.FederationEntity).Elem()
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if field.Type.Kind() != reflect.Slice {
			continue
		}
		tag, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		value, found := claims[tag]
		if found {
			v.Field(i).Set(reflect.ValueOf(value))
		}
	}
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

// GuessMultilingualDisplayNames collects display names for all present metadata types
// with support for multiple languages according to BCP47 (RFC5646).
// The returned map has entity types as keys and maps of language tags to display names as values.
// An empty string language tag represents the default/untagged value.
func (m Metadata) GuessMultilingualDisplayNames() map[string]map[string]string {
	displayNames := make(map[string]map[string]string)
	m.collectDefaultDisplayNames(displayNames)
	m.collectLanguageTaggedDisplayNames(displayNames)
	return displayNames
}

// collectDefaultDisplayNames extracts default (untagged) display names from metadata fields
func (m Metadata) collectDefaultDisplayNames(result map[string]map[string]string) {
	value := reflect.ValueOf(m)
	typ := value.Type()

	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if !isValidPointerField(field) {
			continue
		}

		entityTag := getEntityTag(typ.Field(i))
		ensureLanguageMapExists(result, entityTag)

		elem := field.Elem()
		elemType := elem.Type()

		// First try to find DisplayName field
		if displayName := findDisplayName(elem, elemType); displayName != "" {
			result[entityTag][""] = displayName
			continue
		}

		// If no DisplayName, look for fallback fields
		if fallbackName := findFallbackName(elem, elemType); fallbackName != "" {
			result[entityTag][""] = fallbackName
		}
	}
}

// collectLanguageTaggedDisplayNames extracts language-tagged display names from Extra fields
func (m Metadata) collectLanguageTaggedDisplayNames(result map[string]map[string]string) {
	value := reflect.ValueOf(m)
	typ := value.Type()

	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if !isValidPointerField(field) {
			continue
		}

		entityTag := getEntityTag(typ.Field(i))
		elem := field.Elem()
		elemType := elem.Type()

		extraField, hasExtra := findExtraField(elem, elemType)
		if !hasExtra || extraField.IsNil() {
			continue
		}

		// Process language-tagged display names from Extra
		extraMap := extraField.Interface().(map[string]interface{})
		for key, val := range extraMap {
			if !strings.HasPrefix(key, "display_name#") {
				continue
			}

			langTag := strings.TrimPrefix(key, "display_name#")
			if strVal, ok := val.(string); ok && strVal != "" {
				ensureLanguageMapExists(result, entityTag)
				result[entityTag][langTag] = strVal
			}
		}
	}
}

// isValidPointerField checks if a field is a non-nil pointer
func isValidPointerField(field reflect.Value) bool {
	return field.Kind() == reflect.Ptr && !field.IsNil()
}

// getEntityTag extracts the entity tag from a struct field
func getEntityTag(structField reflect.StructField) string {
	entityTag := structField.Tag.Get("json")
	return strings.TrimSuffix(entityTag, ",omitempty")
}

// ensureLanguageMapExists ensures that a language map exists for the given entity type
func ensureLanguageMapExists(result map[string]map[string]string, entityTag string) {
	if result[entityTag] == nil {
		result[entityTag] = make(map[string]string)
	}
}

// findDisplayName searches for a DisplayName field in a struct and returns its value
func findDisplayName(elem reflect.Value, elemType reflect.Type) string {
	for j := 0; j < elem.NumField(); j++ {
		subField := elem.Field(j)
		subStructField := elemType.Field(j)
		jsonTag := subStructField.Tag.Get("json")

		if strings.HasPrefix(jsonTag, "display_name") && subField.Kind() == reflect.String {
			displayName := subField.String()
			if displayName != "" {
				return displayName
			}
		}
	}
	return ""
}

// findFallbackName searches for fallback name fields in a struct and returns the first non-empty one
func findFallbackName(elem reflect.Value, elemType reflect.Type) string {
	fallbackFields := []string{
		"OrganizationName",
		"ClientName",
		"ResourceName",
	}

	for j := 0; j < elem.NumField(); j++ {
		subField := elem.Field(j)
		subStructField := elemType.Field(j)
		fieldName := subStructField.Name

		for _, fallbackField := range fallbackFields {
			if fieldName == fallbackField && subField.Kind() == reflect.String {
				fallbackName := subField.String()
				if fallbackName != "" {
					return fallbackName
				}
			}
		}
	}
	return ""
}

// findExtraField looks for an Extra field in a struct and returns it if found
func findExtraField(elem reflect.Value, elemType reflect.Type) (reflect.Value, bool) {
	for j := 0; j < elem.NumField(); j++ {
		if elemType.Field(j).Name == "Extra" {
			return elem.Field(j), true
		}
	}
	return reflect.Value{}, false
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

				if jsonTag == tag && subField.Kind() == reflect.Slice {
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

// IterateMultilingualStringClaim collects a claim that has a string value for all metadata
// types and calls the iterator on it with language tag information.
// This is used for human-readable claims that can be represented in multiple languages
// according to BCP47 (RFC5646).
//
// The function first processes the default/untagged values using IterateStringClaim,
// then looks for language-tagged values in the Extra field of each metadata type.
// Language-tagged values are expected to be stored in a map under a key with the
// format "<claim>_lang" (e.g., "description_lang").
//
// The iterator function is called with three parameters:
// - entityType: The type of entity (e.g., "openid_provider")
// - langTag: The language tag (empty string for default/untagged values)
// - value: The string value in the specified language
//
// Example language tags:
// - "" (empty string): Default/untagged value
// - "en": English
// - "fr": French
// - "en-US": American English
// - "zh-Hans": Simplified Chinese
func (m Metadata) IterateMultilingualStringClaim(tag string, iterator func(entityType, langTag, value string)) {
	// First, handle the default case (no language tag)
	m.IterateStringClaim(
		tag, func(entityType, value string) {
			iterator(entityType, "", value)
		},
	)

	// Then check for language-tagged values in Extra
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

			// Check if this entity type has an Extra field
			var extraField reflect.Value
			var hasExtra bool
			for j := 0; j < elem.NumField(); j++ {
				subStructField := elemType.Field(j)
				if subStructField.Name == "Extra" {
					extraField = elem.Field(j)
					hasExtra = true
					break
				}
			}

			if hasExtra && !extraField.IsNil() {
				// Look for language-tagged values in Extra
				extraMap := extraField.Interface().(map[string]interface{})
				for key, val := range extraMap {
					// Check if the key follows the pattern "tag#langTag"
					if strings.HasPrefix(key, tag+"#") {
						langTag := strings.TrimPrefix(key, tag+"#")
						if strVal, ok := val.(string); ok && strVal != "" {
							iterator(entityTag, langTag, strVal)
						}
					}
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
