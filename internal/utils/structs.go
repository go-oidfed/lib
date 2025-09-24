package utils

import (
	"encoding/base64"
	"reflect"
	"slices"
	"strings"

	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/sha3"
)

// NilAllExceptByTag sets all fields of a struct to their zero values except for
// the fields with the specified JSON tags.
func NilAllExceptByTag(v interface{}, jsonTags []string) {
	if v == nil {
		return
	}
	val := reflect.ValueOf(v).Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)
		if fieldType.Name == "Extra" &&
			fieldType.Type == reflect.TypeOf(map[string]any{}) &&
			!field.IsNil() {
			// We already checked the field's type, so this type assertion can't fail
			asMap := field.Interface().(map[string]any)
			sanitized := map[string]any{}
			for key, value := range asMap {
				if slices.Contains(jsonTags, key) {
					sanitized[key] = value
				}
			}

			field.Set(reflect.ValueOf(sanitized))
			continue
		}
		tag := fieldType.Tag.Get("json")

		// Handle the case where the tag includes ",omitempty" or other options
		tagParts := strings.Split(tag, ",")
		baseTag := tagParts[0]

		if baseTag == "" {
			// If no json tag is present, use the field name as the tag
			baseTag = fieldType.Name
		}

		// If this is none of the fields to keep, set it to its zero value
		if !slices.Contains(jsonTags, baseTag) {
			field.Set(reflect.Zero(field.Type()))
		}
	}
}

// HashStruct hashes a struct using msgpack and SHA3-256.
func HashStruct(v any) (string, error) {
	data, err := msgpack.Marshal(v)
	if err != nil {
		return "", err
	}
	hash := sha3.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
