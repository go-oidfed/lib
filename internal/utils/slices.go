package utils

import (
	"reflect"
)

// ReflectSliceCast casts a slice to another type using reflection
func ReflectSliceCast(slice, newType any) any {
	if !IsSlice(slice) {
		return slice
	}
	typeType := reflect.TypeOf(newType)
	sliceV := reflect.ValueOf(slice)
	out := reflect.MakeSlice(typeType, sliceV.Len(), sliceV.Len())
	for i := 0; i < sliceV.Len(); i++ {
		vv := sliceV.Index(i)
		var v reflect.Value
		// This is stupid and has faults, but I did not find a better way
		switch typeType.Elem().Kind() {
		case reflect.Bool:
			v = reflect.ValueOf(vv.Interface().(bool))
		case reflect.Int:
			v = reflect.ValueOf(vv.Interface().(int))
		case reflect.Int8:
			v = reflect.ValueOf(vv.Interface().(int8))
		case reflect.Int16:
			v = reflect.ValueOf(vv.Interface().(int16))
		case reflect.Int32:
			v = reflect.ValueOf(vv.Interface().(int32))
		case reflect.Int64:
			v = reflect.ValueOf(vv.Interface().(int64))
		case reflect.Uint:
			v = reflect.ValueOf(vv.Interface().(uint))
		case reflect.Uint8:
			v = reflect.ValueOf(vv.Interface().(uint8))
		case reflect.Uint16:
			v = reflect.ValueOf(vv.Interface().(uint16))
		case reflect.Uint32:
			v = reflect.ValueOf(vv.Interface().(uint32))
		case reflect.Uint64:
			v = reflect.ValueOf(vv.Interface().(uint64))
		case reflect.Uintptr:
			v = reflect.ValueOf(vv.Interface().(*uint))
		case reflect.Float32:
			v = reflect.ValueOf(vv.Interface().(float32))
		case reflect.Float64:
			v = reflect.ValueOf(vv.Interface().(float64))
		case reflect.Interface:
			v = vv
		case reflect.String:
			v = reflect.ValueOf(vv.Interface().(string))
		default:
			v = vv.Convert(typeType.Elem())
		}
		out.Index(i).Set(v)
	}
	return out.Interface()
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
