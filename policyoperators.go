package oidfed

import (
	"reflect"

	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/internal/utils"
)

// PolicyOperator is an interface implemented by policy operators
type PolicyOperator interface {
	// Merge merges two policy operator values and returns the result
	Merge(a, b any, pathInfo string) (any, error)
	// Apply applies the policy operator value to the attribute value and returns the result
	Apply(value any, valueSet bool, policyValue any, essential bool, pathInfo string) (any, bool, error)
	// Name returns the PolicyOperatorName
	Name() PolicyOperatorName
	// MayCombineWith gives a list of PolicyOperatorName with which this PolicyOperator may be combined
	MayCombineWith() []PolicyOperatorName
}

// Constants for PolicyOperatorNames
const (
	PolicyOperatorValue      PolicyOperatorName = "value"
	PolicyOperatorDefault    PolicyOperatorName = "default"
	PolicyOperatorAdd        PolicyOperatorName = "add"
	PolicyOperatorOneOf      PolicyOperatorName = "one_of"
	PolicyOperatorSubsetOf   PolicyOperatorName = "subset_of"
	PolicyOperatorSupersetOf PolicyOperatorName = "superset_of"
	PolicyOperatorEssential  PolicyOperatorName = "essential"
)

// OperatorOrder defines the order in which the PolicyOperator are applied.
// If custom PolicyOperator are implemented they must be added to this slice at the correct position
var OperatorOrder = []PolicyOperatorName{
	PolicyOperatorValue,
	PolicyOperatorAdd,
	PolicyOperatorDefault,
	PolicyOperatorOneOf,
	PolicyOperatorSubsetOf,
	PolicyOperatorSupersetOf,
	PolicyOperatorEssential,
}

var operators map[PolicyOperatorName]PolicyOperator

// RegisterPolicyOperator registers a new PolicyOperator and therefore makes it available to be used
func RegisterPolicyOperator(operator PolicyOperator) {
	operators[operator.Name()] = operator
}

type policyOperator struct {
	name        PolicyOperatorName
	merger      func(a, b any, pathInfo string) (any, error)
	applier     func(value any, valueSet bool, policyValue any, essential bool, pathInfo string) (any, bool, error)
	combineWith []PolicyOperatorName
}

// Name implements the PolicyOperator interface
func (op policyOperator) Name() PolicyOperatorName {
	return op.name
}

// Merge implements the PolicyOperator interface
func (op policyOperator) Merge(a, b any, pathInfo string) (any, error) {
	return op.merger(a, b, pathInfo)
}

// Apply implements the PolicyOperator interface
func (op policyOperator) Apply(value any, valueSet bool, policyValue any, essential bool, pathInfo string) (
	any, bool, error,
) {
	return op.applier(value, valueSet, policyValue, essential, pathInfo)
}

// MayCombineWith implements the PolicyOperator interface
func (op policyOperator) MayCombineWith() []PolicyOperatorName {
	return op.combineWith
}

// NewPolicyOperator creates a new PolicyOperator from the passed functions and PolicyOperatorName
func NewPolicyOperator(
	name PolicyOperatorName,
	merger func(a, b any, pathInfo string) (any, error),
	applier func(value any, valueSet bool, policyValue any, essential bool, pathInfo string) (any, bool, error),
	mayCombineWith []PolicyOperatorName,
) PolicyOperator {
	return policyOperator{
		name:        name,
		merger:      merger,
		applier:     applier,
		combineWith: mayCombineWith,
	}
}

var policyOperatorAdd = NewPolicyOperator(
	PolicyOperatorAdd,
	func(a, b any, _ string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		return utils.ReflectUnion(a, b), nil
	},
	func(value any, valueSet bool, policyValue any, _ bool, _ string) (
		any, bool, error,
	) {
		if value == nil {
			return policyValue, policyValue != nil, nil
		}
		if policyValue == nil {
			return value, valueSet, nil
		}
		return utils.ReflectUnion(value, policyValue), true, nil
	},
	[]PolicyOperatorName{
		PolicyOperatorValue,
		PolicyOperatorDefault,
		PolicyOperatorSubsetOf,
		PolicyOperatorSupersetOf,
		PolicyOperatorEssential,
	},
)

var policyOperatorSubsetOf = NewPolicyOperator(
	PolicyOperatorSubsetOf,
	func(a, b any, _ string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		return utils.ReflectIntersect(a, b), nil
	},
	func(
		value any, valueSet bool, policyValue any, essential bool,
		pathInfo string,
	) (any, bool, error) {
		if !valueSet && !essential {
			return value, valueSet, nil
		}
		if policyValue == nil {
			return value, valueSet, nil
		}
		p := utils.Slicify(policyValue)
		if !valueSet { // policyValue is not nil and value is essential
			return value, valueSet, errors.Errorf(
				"policy operator check failed: '%s' not set, but essential and must be one of '%+q'",
				pathInfo, policyValue,
			)
		}
		v := utils.Slicify(value)
		newValue := utils.ReflectIntersect(v, p)
		// if reflect.ValueOf(newValue).Len() == 0 {
		// 	newValue = nil
		// 	if essential {
		// 		return newValue, errors.Errorf(
		// 			"policy operator check failed for '%s': '%+q' is not subset of '%+q' but essential",
		// 			pathInfo, value, p,
		// 		)
		// 	}
		// }
		return newValue, true, nil
	},
	[]PolicyOperatorName{
		PolicyOperatorValue,
		PolicyOperatorAdd,
		PolicyOperatorDefault,
		PolicyOperatorSupersetOf,
		PolicyOperatorEssential,
	},
)

var policyOperatorOneOf = NewPolicyOperator(
	PolicyOperatorOneOf,
	func(a, b any, _ string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		return utils.ReflectIntersect(a, b), nil
	},
	func(
		value any, valueSet bool, policyValue any, essential bool,
		pathInfo string,
	) (any, bool, error) {
		if !valueSet && !essential {
			return value, valueSet, nil
		}
		if policyValue == nil {
			return value, valueSet, nil
		}
		p := utils.Slicify(policyValue)
		if !valueSet { // policyValue is not nil and value is essential
			return value, valueSet, errors.Errorf(
				"policy operator check failed: '%s' not set, but essential and must be one of '%+q'",
				pathInfo, policyValue,
			)
		}
		if !utils.ReflectSliceContains(value, p) {
			return value, valueSet, errors.Errorf(
				"policy operator check failed for '%s': '%+q' is not one of '%+q'",
				pathInfo, value, p,
			)
		}
		return value, valueSet, nil
	},
	[]PolicyOperatorName{
		PolicyOperatorValue,
		PolicyOperatorDefault,
		PolicyOperatorEssential,
	},
)

var policyOperatorSupersetOf = NewPolicyOperator(
	PolicyOperatorSupersetOf,
	func(a, b any, _ string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		return utils.ReflectUnion(a, b), nil
	},
	func(
		value any, valueSet bool, policyValue any, essential bool,
		pathInfo string,
	) (any, bool, error) {
		if !valueSet && !essential {
			return value, valueSet, nil
		}
		if policyValue == nil {
			return value, valueSet, nil
		}
		p := utils.Slicify(policyValue)
		if !valueSet { // policyValue is not nil and value is essential
			return value, valueSet, errors.Errorf(
				"policy operator check failed: '%s' not set, but essential and must be superset of '%+q'",
				pathInfo, policyValue,
			)
		}

		v := utils.Slicify(value)
		if !utils.ReflectIsSupersetOf(v, p) {
			return value, valueSet, errors.Errorf(
				"policy operator check failed for '%s': '%+q' is not a superset of '%+q'",
				pathInfo, v, p,
			)
		}
		return value, valueSet, nil
	},
	[]PolicyOperatorName{
		PolicyOperatorValue,
		PolicyOperatorAdd,
		PolicyOperatorDefault,
		PolicyOperatorSubsetOf,
		PolicyOperatorEssential,
	},
)

var policyOperatorValue = NewPolicyOperator(
	PolicyOperatorValue,
	func(a, b any, pathInfo string) (any, error) {
		// if a == nil {
		// 	return b, nil
		// }
		// if b == nil {
		// 	return a, nil
		// }
		if utils.SliceEqual(a, b) {
			return a, nil
		}
		return nil, errors.Errorf(
			"conflicting values '%v' and '%v' when merging '%s' operator in '%s'", a, b, PolicyOperatorValue, pathInfo,
		)
	},
	func(value any, _ bool, policyValue any, _ bool, _ string) (any, bool, error) {
		if policyValue == nil {
			return nil, false, nil
		}
		return utils.ReflectSliceCast(policyValue, utils.Slicify(value)), true, nil
	},
	[]PolicyOperatorName{
		PolicyOperatorAdd,
		PolicyOperatorDefault,
		PolicyOperatorOneOf,
		PolicyOperatorSubsetOf,
		PolicyOperatorSupersetOf,
		PolicyOperatorEssential,
	},
)

var policyOperatorDefault = NewPolicyOperator(
	PolicyOperatorDefault,
	func(a, b any, pathInfo string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		if utils.SliceEqual(a, b) {
			return a, nil
		}
		return nil, errors.Errorf(
			"conflicting values '%v' and '%v' when merging '%s' operator in '%s'", a, b, PolicyOperatorDefault,
			pathInfo,
		)
	},
	func(value any, valueSet bool, policyValue any, _ bool, _ string) (any, bool, error) {
		if !valueSet && (value == nil || reflect.ValueOf(value).IsZero()) {
			return utils.ReflectSliceCast(policyValue, utils.Slicify(value)), true, nil
		}
		return value, valueSet, nil
	},
	[]PolicyOperatorName{
		PolicyOperatorValue,
		PolicyOperatorAdd,
		PolicyOperatorOneOf,
		PolicyOperatorSubsetOf,
		PolicyOperatorSupersetOf,
		PolicyOperatorEssential,
	},
)

var policyOperatorEssential = NewPolicyOperator(
	PolicyOperatorEssential,
	func(a, b any, _ string) (any, error) {
		ab, aok := a.(bool)
		bb, bok := b.(bool)
		if !aok && !bok {
			return false, nil
		}
		if !aok {
			return bb, nil
		}
		if !bok {
			return ab, nil
		}
		return ab || bb, nil
	},
	func(value any, valueSet bool, policyValue any, _ bool, pathInfo string) (any, bool, error) {
		if policyValue == nil {
			return value, valueSet, nil
		}
		if essential, eok := policyValue.(bool); eok && essential {
			isNotSet := !valueSet && (value == nil || (utils.IsSlice(value) && reflect.ValueOf(value).IsNil()) || (!utils.IsSlice(value) && reflect.ValueOf(value).IsZero()))
			isEmptyNonSlice := valueSet && !utils.IsSlice(value) && reflect.ValueOf(value).IsZero()
			if isNotSet || isEmptyNonSlice {
				return nil, valueSet, errors.Errorf("metadata value for '%s' not set but required", pathInfo)
			}
		}
		return value, valueSet, nil
	},
	nil,
)

func init() {
	operators = make(map[PolicyOperatorName]PolicyOperator)
	RegisterPolicyOperator(policyOperatorSubsetOf)
	RegisterPolicyOperator(policyOperatorOneOf)
	RegisterPolicyOperator(policyOperatorSupersetOf)
	RegisterPolicyOperator(policyOperatorAdd)
	RegisterPolicyOperator(policyOperatorValue)
	RegisterPolicyOperator(policyOperatorDefault)
	RegisterPolicyOperator(policyOperatorEssential)
}
