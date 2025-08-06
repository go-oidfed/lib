package oidfed

import (
	"reflect"
	"strings"
)

// MultilingualString represents a string that can be represented in multiple languages.
//
// The map keys are language tags:
// - Empty string ("") represents the default/untagged value
// - Other keys are BCP47 language tags (e.g., "en", "fr", "en-US")
//
// The map values are the string representations in each language.
// This type is used to store human-readable UI claims in multiple languages.
type MultilingualString map[string]string

// String returns a single string representation of the multilingual string.
//
// The method follows these rules for selecting which value to return:
// 1. If a default/untagged value (empty string key) exists and is non-empty, return it
// 2. Otherwise, return the first (random order) non-empty value found
// 3. If no values exist or all are empty, return an empty string
//
// This ensures that existing code continues to work with the default language value
// while still supporting multilingual capabilities.
func (m MultilingualString) String() string {
	if val, ok := m[""]; ok && val != "" {
		return val
	}

	for _, v := range m {
		if v != "" {
			return v
		}
	}

	return ""
}

// MultilingualUIInfo is a version of UIInfo that supports multilingual values.
// This type is used internally for processing UI claims in multiple languages.
//
// It replaces the string fields in UIInfo with MultilingualString fields to support
// multiple language representations of the same information. The Keywords field
// remains as a string slice since it's not typically language-specific.
//
// This type is not exposed directly in the API but is used internally to convert
// between the standard UIInfo type and multilingual representations. It may be used
// by third-party applications.
type MultilingualUIInfo struct {
	DisplayName    MultilingualString `json:"display_name,omitempty"`
	Description    MultilingualString `json:"description,omitempty"`
	Keywords       []string           `json:"keywords,omitempty"`
	LogoURI        MultilingualString `json:"logo_uri,omitempty"`
	PolicyURI      MultilingualString `json:"policy_uri,omitempty"`
	InformationURI MultilingualString `json:"information_uri,omitempty"`
	Extra          map[string]any     `json:"-"`
}

// setMultilingualUIInfoField sets a field in UIInfo with support for multiple languages.
// It stores the value in the appropriate field based on the JSON tag and language tag.
//
// Parameters:
// - entityType: The type of entity (e.g., "openid_provider")
// - jsonTag: The JSON tag of the field to set (e.g., "display_name")
// - langTag: The language tag according to BCP47 (empty string for default/untagged value)
// - value: The value to set
//
// Returns an error if the value cannot be set.
func (e *CollectedEntity) setMultilingualUIInfoField(entityType, jsonTag, langTag string, value any) error {
	if e.UIInfos == nil {
		e.UIInfos = make(map[string]UIInfo)
	}

	uiInfo := e.UIInfos[entityType]

	// Convert the existing UIInfo to MultilingualUIInfo if needed
	multiUIInfo := convertToMultilingualUIInfo(uiInfo)

	// Set the value in the appropriate field
	multiUIInfoValue := reflect.ValueOf(&multiUIInfo).Elem()
	multiUIInfoType := multiUIInfoValue.Type()

	fieldFound := false

	for i := 0; i < multiUIInfoType.NumField(); i++ {
		structField := multiUIInfoType.Field(i)
		tag := structField.Tag.Get("json")
		tagName, _, _ := strings.Cut(tag, ",")

		if tagName == jsonTag {
			fieldValue := multiUIInfoValue.Field(i)
			if fieldValue.CanSet() {
				// For MultilingualString fields
				if fieldValue.Type() == reflect.TypeOf(MultilingualString{}) {
					if strValue, ok := value.(string); ok {
						// Initialize the map if it's nil
						if fieldValue.IsNil() {
							fieldValue.Set(reflect.MakeMap(fieldValue.Type()))
						}

						// Set the value for the specified language tag
						fieldValue.SetMapIndex(reflect.ValueOf(langTag), reflect.ValueOf(strValue))
						fieldFound = true
						break
					}
				} else {
					// For other fields (like Keywords)
					val := reflect.ValueOf(value)
					if val.Type().AssignableTo(fieldValue.Type()) {
						fieldValue.Set(val)
						fieldFound = true
						break
					}
				}
			}
		}
	}

	if !fieldFound {
		if multiUIInfo.Extra == nil {
			multiUIInfo.Extra = make(map[string]any)
		}
		multiUIInfo.Extra[jsonTag] = value
	}

	// Convert back to UIInfo and store
	e.UIInfos[entityType] = convertToUIInfo(multiUIInfo)
	return nil
}

// convertToMultilingualUIInfo converts a UIInfo to a MultilingualUIInfo
// It handles both the default values from UIInfo fields and language-tagged values
// from the Extra map using the "tag#langTag" format.
func convertToMultilingualUIInfo(info UIInfo) MultilingualUIInfo {
	multiInfo := MultilingualUIInfo{
		Keywords: info.Keywords,
		Extra:    make(map[string]any),
	}

	// Copy the Extra map
	if info.Extra != nil {
		for k, v := range info.Extra {
			multiInfo.Extra[k] = v
		}
	}

	// Initialize MultilingualString fields with default values from UIInfo
	// Create a helper function to initialize MultilingualString fields
	initMultilingualField := func(value string) MultilingualString {
		if value != "" {
			return MultilingualString{"": value}
		}
		return MultilingualString{}
	}

	multiInfo.DisplayName = initMultilingualField(info.DisplayName)
	multiInfo.Description = initMultilingualField(info.Description)
	multiInfo.LogoURI = initMultilingualField(info.LogoURI)
	multiInfo.PolicyURI = initMultilingualField(info.PolicyURI)
	multiInfo.InformationURI = initMultilingualField(info.InformationURI)

	// Process language-tagged values from Extra map
	for key, val := range info.Extra {
		// Check for keys in the format "tag#langTag"
		if idx := strings.Index(key, "#"); idx > 0 {
			fieldName := key[:idx]
			langTag := key[idx+1:]

			if strVal, ok := val.(string); ok && strVal != "" {
				switch fieldName {
				case "display_name":
					multiInfo.DisplayName[langTag] = strVal
				case "description":
					multiInfo.Description[langTag] = strVal
				case "logo_uri":
					multiInfo.LogoURI[langTag] = strVal
				case "policy_uri":
					multiInfo.PolicyURI[langTag] = strVal
				case "information_uri":
					multiInfo.InformationURI[langTag] = strVal
				}
			}
		}
	}

	return multiInfo
}

// convertToUIInfo converts a MultilingualUIInfo to a UIInfo
// It sets the default/untagged values as the primary values in UIInfo fields
// and stores language-tagged values in the Extra map using the "tag#langTag" format.
func convertToUIInfo(multiInfo MultilingualUIInfo) UIInfo {
	info := UIInfo{
		Keywords: multiInfo.Keywords,
		Extra:    make(map[string]any),
	}

	// Copy the Extra map
	if multiInfo.Extra != nil {
		for k, v := range multiInfo.Extra {
			info.Extra[k] = v
		}
	}

	// Convert MultilingualString fields to string (using default/untagged values)
	info.DisplayName = multiInfo.DisplayName.String()
	info.Description = multiInfo.Description.String()
	info.LogoURI = multiInfo.LogoURI.String()
	info.PolicyURI = multiInfo.PolicyURI.String()
	info.InformationURI = multiInfo.InformationURI.String()

	// Store language-tagged values in the Extra map using the "tag#langTag" format
	storeLanguageTaggedValues := func(fieldName string, values MultilingualString) {
		for langTag, value := range values {
			if langTag != "" && value != "" { // Skip default/untagged value
				info.Extra[fieldName+"#"+langTag] = value
			}
		}
	}

	// Process all multilingual fields
	storeLanguageTaggedValues("display_name", multiInfo.DisplayName)
	storeLanguageTaggedValues("description", multiInfo.Description)
	storeLanguageTaggedValues("logo_uri", multiInfo.LogoURI)
	storeLanguageTaggedValues("policy_uri", multiInfo.PolicyURI)
	storeLanguageTaggedValues("information_uri", multiInfo.InformationURI)

	return info
}
