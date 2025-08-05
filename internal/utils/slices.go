package utils

import (
	"reflect"
)

// ReflectSliceCast converts a slice to another type using reflection.
// Parameters:
//   - slice: source slice to convert
//   - newType: target type for the slice elements
//
// Retur
// Returns:
//   - converted slice or original value if input is not a slice
func ReflectSliceCast(slice, newType any) any {
	if !IsSlice(slice) {
		return slice
	}

	typeType := reflect.TypeOf(newType)
	sliceV := reflect.ValueOf(slice)
	out := reflect.MakeSlice(typeType, sliceV.Len(), sliceV.Len())

	for i := 0; i < sliceV.Len(); i++ {
		sourceVal := sliceV.Index(i)
		convertedVal := convertToTargetType(sourceVal, typeType.Elem())
		out.Index(i).Set(convertedVal)
	}

	return out.Interface()
}

// convertToTargetType converts a reflect.Value to the target type.
// It handles primitive types explicitly and falls back to generic conversion for other types.
func convertToTargetType(val reflect.Value, targetType reflect.Type) reflect.Value {
	if targetType.Kind() == reflect.Interface {
		return val
	}

	// Get the underlying interface value
	srcInterface := val.Interface()

	// Handle primitive types
	switch targetType.Kind() {
	case reflect.Bool:
		return reflect.ValueOf(srcInterface.(bool))
	case reflect.Int:
		return reflect.ValueOf(srcInterface.(int))
	case reflect.Int8:
		return reflect.ValueOf(srcInterface.(int8))
	case reflect.Int16:
		return reflect.ValueOf(srcInterface.(int16))
	case reflect.Int32:
		return reflect.ValueOf(srcInterface.(int32))
	case reflect.Int64:
		return reflect.ValueOf(srcInterface.(int64))
	case reflect.Uint:
		return reflect.ValueOf(srcInterface.(uint))
	case reflect.Uint8:
		return reflect.ValueOf(srcInterface.(uint8))
	case reflect.Uint16:
		return reflect.ValueOf(srcInterface.(uint16))
	case reflect.Uint32:
		return reflect.ValueOf(srcInterface.(uint32))
	case reflect.Uint64:
		return reflect.ValueOf(srcInterface.(uint64))
	case reflect.Float32:
		return reflect.ValueOf(srcInterface.(float32))
	case reflect.Float64:
		return reflect.ValueOf(srcInterface.(float64))
	case reflect.String:
		return reflect.ValueOf(srcInterface.(string))
	default:
		// For other types, try to convert using reflection
		return val.Convert(targetType)
	}
}

// ReflectSliceContains checks if a slice contains a value using reflection
func ReflectSliceContains(v, slice any) bool {
	if !IsSlice(slice) {
		return false
	}
	sliceV := reflect.ValueOf(slice)
	for i := 0; i < sliceV.Len(); i++ {
		if reflect.DeepEqual(v, sliceV.Index(i).Interface()) {
			return true
		}
	}
	return false
}

// ReflectUnion uses reflection to compute the union of two slices
func ReflectUnion(a, b any) any {
	as := Slicify(a)
	bs := Slicify(b)
	out := reflect.ValueOf(as)
	bV := reflect.ValueOf(bs)
	if bV.Len() == 0 {
		return out.Interface()
	}
	if out.Len() == 0 || out.Index(0).Type() != bV.Index(0).Type() {
		bs = ReflectSliceCast(bs, as)
		bV = reflect.ValueOf(bs)
	}
	if out.Len() == 0 {
		return bV.Interface()
	}
	for i := 0; i < bV.Len(); i++ {
		v := bV.Index(i)
		if !ReflectSliceContains(v.Interface(), out.Interface()) {
			out = reflect.Append(out, v)
		}
	}
	return out.Interface()
}

// ReflectIntersect uses reflection to compute the intersection of two slices
func ReflectIntersect(a, b any) any {
	as := Slicify(a)
	bs := Slicify(b)
	aV := reflect.ValueOf(as)
	if aV.Type() != reflect.ValueOf(bs).Type() {
		bs = ReflectSliceCast(bs, as)
	}
	out := reflect.New(reflect.TypeOf(as)).Elem()
	for i := 0; i < aV.Len(); i++ {
		v := aV.Index(i)
		if ReflectSliceContains(v.Interface(), bs) {
			out = reflect.Append(out, v)
		}
	}
	return out.Interface()
}

// ReflectIsSubsetOf uses reflection to check if a slice is a subset of another
func ReflectIsSubsetOf(is, of any) bool {
	is = Slicify(is)
	of = Slicify(of)
	isV := reflect.ValueOf(is)
	for i := 0; i < isV.Len(); i++ {
		v := isV.Index(i)
		if !ReflectSliceContains(v.Interface(), of) {
			return false
		}
	}
	return true
}

// ReflectIsSupersetOf uses reflection to check if a slice is a superset of another
func ReflectIsSupersetOf(is, of any) bool {
	return ReflectIsSubsetOf(of, is)
}

// IsSlice uses reflection to check if an interface{} is a slice
func IsSlice(v interface{}) bool {
	if !reflect.ValueOf(v).IsValid() {
		return false
	}
	return reflect.TypeOf(v).Kind() == reflect.Slice
}

// SliceEqual uses reflection to check if two slices contain the same elements; order does not matter,
// assumes no duplicate entries in a slice
func SliceEqual(a, b interface{}) bool {
	if a == nil || b == nil {
		return a == b
	}
	as := Slicify(a)
	bs := Slicify(b)
	aV := reflect.ValueOf(as)
	bV := reflect.ValueOf(bs)
	if aV.Len() != bV.Len() {
		return false
	}
	for i := 0; i < aV.Len(); i++ {
		if !ReflectSliceContains(aV.Index(i).Interface(), bs) {
			return false
		}
	}
	return true
}

// Slicify checks if an interface{} is a slice and if not returns a slice of the same type (as an interface{})
// containing the value, otherwise it returns the original slice
func Slicify(in any) any {
	if in == nil {
		return nil
	}
	if IsSlice(in) {
		return in
	}

	out := reflect.New(reflect.SliceOf(reflect.TypeOf(in))).Elem()
	out = reflect.Append(out, reflect.ValueOf(in))
	return out.Interface()
}
