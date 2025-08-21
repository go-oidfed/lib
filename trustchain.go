package oidfed

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/zachmann/go-utils/maputils"
	"golang.org/x/crypto/sha3"
	"tideland.dev/go/slices"

	"github.com/go-oidfed/lib/cache"
	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/unixtime"
)

// TrustChain is a slice of *EntityStatements
type TrustChain []*EntityStatement

func (c TrustChain) hash() ([]byte, error) {
	data, err := msgpack.Marshal(c)
	if err != nil {
		return nil, err
	}
	hash := sha3.Sum256(data)
	return hash[:], nil
}

// PathLen returns the path len of a chain as defined by the spec,
// i.e. the number of intermediates
func (c TrustChain) PathLen() int {
	// The chain consists of the following stmts:
	// Subject's Entity Configuration
	// Statement(s) about the the subordinate
	// TA's Entity Configuration
	//
	// Therefore, there are at least 3 statements in the chain; in this case
	// there are no intermediates.
	// The number of intermediates is len()-3
	if len(c) <= 3 {
		return 0
	}
	return len(c) - 3
}

// ExpiresAt returns the expiration time of the TrustChain as a UNIX time stamp
func (c TrustChain) ExpiresAt() unixtime.Unixtime {
	if len(c) == 0 {
		return unixtime.Unixtime{}
	}
	exp := c[0].ExpiresAt
	for i := 1; i < len(c); i++ {
		if e := c[i].ExpiresAt; e.Before(exp.Time) {
			exp = e
		}
	}
	return exp
}

// Metadata returns the final Metadata for this TrustChain,
// i.e. the Metadata of the leaf entity with MetadataPolicies of authorities applied to it.
func (c TrustChain) Metadata() (*Metadata, error) {
	if m, set, err := c.cacheGetMetadata(); err != nil {
		internal.Log(err.Error())
	} else if set {
		return m, nil
	}
	if len(c) == 0 {
		return nil, errors.New("trust chain empty")
	}
	if len(c) == 1 {
		return c[0].Metadata, nil
	}
	metadataPolicies := make([]*MetadataPolicies, len(c))
	critPolicies := make(map[PolicyOperatorName]struct{})
	for i, stmt := range c {
		metadataPolicies[i] = stmt.MetadataPolicy
		for _, mpoc := range stmt.MetadataPolicyCrit {
			critPolicies[mpoc] = struct{}{}
		}
	}
	unsupportedCritPolicies := slices.Subtract(maputils.Keys(critPolicies), OperatorOrder)
	if len(unsupportedCritPolicies) > 0 {
		return nil, errors.Errorf(
			"the following metadata policy operators are critical but not understood: %v",
			unsupportedCritPolicies,
		)
	}

	combinedPolicy, err := MergeMetadataPolicies(metadataPolicies...)
	if err != nil {
		return nil, err
	}
	metadataFromSuperior := c[1].Metadata
	m := c[0].Metadata
	if m == nil {
		if metadataFromSuperior == nil {
			m = &Metadata{}
		} else {
			m = metadataFromSuperior
		}
	} else if metadataFromSuperior != nil {
		mergeMetadata(m, metadataFromSuperior)
	}
	final, err := m.ApplyPolicy(combinedPolicy)
	if err != nil {
		return nil, err
	}
	if err = c.cacheSetMetadata(final); err != nil {
		internal.Log(err.Error())
	}
	return final, nil
}

// mergeMetadata merges values from source into target, with source values taking precedence.
// Any value set in source will overwrite the corresponding value in target.
func mergeMetadata(target, source *Metadata) {
	if source == nil {
		return
	}

	targetVal := reflect.ValueOf(target).Elem()
	sourceVal := reflect.ValueOf(source).Elem()
	typ := targetVal.Type()

	// Iterate through all fields of Metadata struct
	for i := 0; i < targetVal.NumField(); i++ {
		fieldName := typ.Field(i).Name

		// Skip the Extra field as it needs special handling
		if fieldName == "Extra" {
			continue
		}

		targetField := targetVal.Field(i)
		sourceField := sourceVal.Field(i)

		// Only proceed if source field is not nil
		if sourceField.Kind() == reflect.Ptr && !sourceField.IsNil() {
			if targetField.IsNil() {
				// If target field is nil, just copy the source field
				targetField.Set(sourceField)
			} else {
				// Both fields are non-nil pointers to structs, merge their values
				mergeStructFields(targetField.Elem(), sourceField.Elem())
			}
		}
	}

	// Handle Extra field separately
	if source.Extra != nil {
		if target.Extra == nil {
			target.Extra = make(map[string]any)
		}
		for k, v := range source.Extra {
			target.Extra[k] = v
		}
	}
}

// mergeStructFields merges values from source struct into target struct using reflection.
// Any field set in source will overwrite the corresponding field in target.
func mergeStructFields(target, source reflect.Value) {
	// Get the wasSet map from source if it exists
	var wasSetMap map[string]bool
	if wasSetField := source.FieldByName("wasSet"); wasSetField.IsValid() && wasSetField.CanInterface() {
		if m, ok := wasSetField.Interface().(map[string]bool); ok {
			wasSetMap = m
		}
	}

	// Get the wasSet map from target if it exists
	var targetWasSetMap map[string]bool
	if targetWasSetField := target.FieldByName("wasSet"); targetWasSetField.IsValid() && targetWasSetField.CanInterface() {
		if m, ok := targetWasSetField.Interface().(map[string]bool); ok {
			targetWasSetMap = m
		}
	} else if targetWasSetField = target.FieldByName("wasSet"); targetWasSetField.IsValid() && targetWasSetField.CanSet() {
		// If target has a wasSet field but it's nil, initialize it
		newMap := make(map[string]bool)
		targetWasSetField.Set(reflect.ValueOf(newMap))
		targetWasSetMap = newMap
	}

	typ := source.Type()
	// Iterate through all fields of the struct
	for i := 0; i < source.NumField(); i++ {
		field := typ.Field(i)
		fieldName := field.Name

		// Skip the wasSet field
		if fieldName == "wasSet" {
			continue
		}

		sourceField := source.Field(i)
		targetField := target.FieldByName(fieldName)

		// If field doesn't exist in target or can't be set, skip it
		if !targetField.IsValid() || !targetField.CanSet() {
			continue
		}

		// Check if this field was explicitly set in source
		fieldWasSet := wasSetMap == nil || wasSetMap[fieldName]

		// Only overwrite if the field was set in source
		if fieldWasSet && !sourceField.IsZero() {
			// Handle different field types
			if sourceField.Kind() == reflect.Map && targetField.Kind() == reflect.Map {
				// For maps, merge the contents
				if targetField.IsNil() {
					targetField.Set(reflect.MakeMap(targetField.Type()))
				}

				for _, key := range sourceField.MapKeys() {
					value := sourceField.MapIndex(key)
					targetField.SetMapIndex(key, value)
				}
			} else {
				// For other types, just copy the value
				targetField.Set(sourceField)
			}

			// Update the wasSet map in target if it exists
			if targetWasSetMap != nil {
				targetWasSetMap[fieldName] = true
			}
		}
	}

	// Handle Extra field separately if it exists
	extraField := source.FieldByName("Extra")
	if extraField.IsValid() && !extraField.IsNil() {
		targetExtraField := target.FieldByName("Extra")
		if targetExtraField.IsValid() {
			if targetExtraField.IsNil() {
				targetExtraField.Set(reflect.MakeMap(targetExtraField.Type()))
			}

			// Copy all keys from source.Extra to target.Extra
			for _, key := range extraField.MapKeys() {
				value := extraField.MapIndex(key)
				targetExtraField.SetMapIndex(key, value)
			}

			// Mark these fields as set in wasSet if needed
			if targetWasSetMap != nil {
				for _, key := range extraField.MapKeys() {
					if k, ok := key.Interface().(string); ok {
						targetWasSetMap[k] = true
					}
				}
			}
		}
	}
}

// Messages returns the jwts of the TrustChain
func (c TrustChain) Messages() (msgs JWSMessages) {
	for _, cc := range c {
		msgs = append(msgs, cc.jwtMsg)
	}
	return
}

func (c TrustChain) cacheGetMetadata() (
	metadata *Metadata, set bool, err error,
) {
	hash, err := c.hash()
	if err != nil {
		return nil, false, err
	}
	metadata = &Metadata{}
	set, err = cache.Get(
		cache.Key(cache.KeyTrustChainResolvedMetadata, string(hash)), metadata,
	)
	return
}

func (c TrustChain) cacheSetMetadata(metadata *Metadata) error {
	hash, err := c.hash()
	if err != nil {
		return err
	}
	return cache.Set(
		cache.Key(cache.KeyTrustChainResolvedMetadata, string(hash)), metadata,
		unixtime.Until(c.ExpiresAt()),
	)
}
