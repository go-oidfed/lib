package oidfed

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/zachmann/go-utils/maputils"
	"github.com/zachmann/go-utils/sliceutils"

	"github.com/go-oidfed/lib/cache"
	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/internal/utils"
	"github.com/go-oidfed/lib/unixtime"
)

// TrustChain is a slice of *EntityStatements
type TrustChain []*EntityStatement

func (c TrustChain) hash() (string, error) {
	return utils.HashStruct(c)
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
	unsupportedCritPolicies := sliceutils.Subtract(maputils.Keys(critPolicies), OperatorOrder)
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
// wasSetMap returns the internal wasSet map if present and accessible
func wasSetMap(v reflect.Value) map[string]bool {
	f := v.FieldByName("wasSet")
	if !f.IsValid() || f.IsNil() || !f.CanInterface() {
		return nil
	}
	if m, ok := f.Interface().(map[string]bool); ok {
		return m
	}
	return nil
}

// canMerge determines if a field should be merged from source into target
func canMerge(fieldName string, sourceField reflect.Value, sourceWasSet map[string]bool) bool {
	if fieldName == "wasSet" || fieldName == "Extra" {
		return false
	}
	if sourceWasSet != nil && !sourceWasSet[fieldName] {
		return false
	}
	if sourceField.IsZero() {
		return false
	}
	return true
}

// mergeValue merges a single field value, handling maps specially
func mergeValue(targetField, sourceField reflect.Value) {
	if sourceField.Kind() == reflect.Map && targetField.Kind() == reflect.Map {
		if targetField.IsNil() {
			targetField.Set(reflect.MakeMap(targetField.Type()))
		}
		for _, k := range sourceField.MapKeys() {
			targetField.SetMapIndex(k, sourceField.MapIndex(k))
		}
		return
	}
	targetField.Set(sourceField)
}

// mergeExtra merges the Extra map and optionally marks keys in targetWasSet
func mergeExtra(target, source reflect.Value, targetWasSet map[string]bool) {
	se := source.FieldByName("Extra")
	if !se.IsValid() || se.IsNil() {
		return
	}
	te := target.FieldByName("Extra")
	if !te.IsValid() {
		return
	}
	if te.IsNil() {
		te.Set(reflect.MakeMap(te.Type()))
	}
	for _, k := range se.MapKeys() {
		te.SetMapIndex(k, se.MapIndex(k))
		if targetWasSet != nil {
			if s, ok := k.Interface().(string); ok {
				targetWasSet[s] = true
			}
		}
	}
}

func mergeStructFields(target, source reflect.Value) {
	sourceWasSet := wasSetMap(source)
	targetWasSet := wasSetMap(target)

	st := source.Type()
	for i := 0; i < source.NumField(); i++ {
		f := st.Field(i)
		name := f.Name
		sf := source.Field(i)
		tf := target.FieldByName(name)
		if !tf.IsValid() || !tf.CanSet() {
			continue
		}
		if !canMerge(name, sf, sourceWasSet) {
			continue
		}
		mergeValue(tf, sf)
		if targetWasSet != nil {
			targetWasSet[name] = true
		}
	}

	mergeExtra(target, source, targetWasSet)
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
