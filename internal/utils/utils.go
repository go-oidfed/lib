package utils

import (
	"reflect"
)

// Equal compares multiple comparable values for equality
func Equal[C comparable](v C, values ...C) bool {
	for _, vv := range values {
		if v != vv {
			return false
		}
	}
	return true
}

// IsMap uses reflection to check if an interface{} is a map
func IsMap(v interface{}) bool {
	return reflect.TypeOf(v).Kind() == reflect.Map
}
