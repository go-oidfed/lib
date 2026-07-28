package oidfed

import (
	"reflect"

	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/internal/utils"
)

// PolicyVerifier is a function that verifies a MetadataPolicyEntry
type PolicyVerifier func(p MetadataPolicyEntry, pathInfo string) error

var policyVerifiers []PolicyVerifier

// RegisterPolicyVerifier registers a PolicyVerifier
func RegisterPolicyVerifier(v PolicyVerifier) {
	policyVerifiers = append(policyVerifiers, v)
}

func policyVerifierSubsetSupersetOneOf(p MetadataPolicyEntry, pathInfo string) error {
	_, oneof := p[PolicyOperatorOneOf]
	_, subset := p[PolicyOperatorSubsetOf]
	_, superset := p[PolicyOperatorSupersetOf]
	if oneof && (subset || superset) {
		return errors.Errorf(
			"policy_operator '%s' cannot appear beside '%s'/'%s' in policy entry '%s'",
			PolicyOperatorOneOf, PolicyOperatorSubsetOf, PolicyOperatorSupersetOf, pathInfo,
		)
	}
	return nil
}

func policyVerifierSubsetSupersetOf(p MetadataPolicyEntry, pathInfo string) error {
	subsetV, subset := p[PolicyOperatorSubsetOf]
	supersetV, superset := p[PolicyOperatorSupersetOf]
	if !subset || !superset {
		return nil
	}
	if !utils.ReflectIsSubsetOf(supersetV, subsetV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator values '%v' are not all included in the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorSupersetOf,
			supersetV,
			PolicyOperatorSubsetOf,
			subsetV,
		)
	}
	return nil
}

func policyVerifyAddInSubset(p MetadataPolicyEntry, pathInfo string) error {
	subsetV, subset := p[PolicyOperatorSubsetOf]
	addV, addSet := p[PolicyOperatorAdd]
	if !subset || !addSet {
		return nil
	}
	if !utils.ReflectIsSubsetOf(addV, subsetV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator values '%v' are not all included in the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorAdd,
			addV,
			PolicyOperatorSubsetOf,
			subsetV,
		)
	}
	return nil
}

func policyVerifyAddInValue(p MetadataPolicyEntry, pathInfo string) error {
	valueV, valueSet := p[PolicyOperatorValue]
	addV, addSet := p[PolicyOperatorAdd]
	if !valueSet || !addSet {
		return nil
	}
	if !utils.ReflectIsSubsetOf(addV, valueV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator values '%v' are not all included in the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorAdd,
			addV,
			PolicyOperatorValue,
			valueV,
		)
	}
	return nil
}

func policyVerifyDefaultAndValue(p MetadataPolicyEntry, pathInfo string) error {
	valueV, valueSet := p[PolicyOperatorValue]
	_, defaultSet := p[PolicyOperatorDefault]
	if !valueSet || !defaultSet {
		return nil
	}
	if valueV == nil {
		return errors.Errorf(
			"after combining policies '%s': combining '%s' with a null '%s' policy is not allowed.", pathInfo,
			PolicyOperatorDefault, PolicyOperatorValue,
		)
	}
	return nil
}

func policyVerifySubsetOfAndValue(p MetadataPolicyEntry, pathInfo string) error {
	valueV, valueSet := p[PolicyOperatorValue]
	subsetV, subsetSet := p[PolicyOperatorSubsetOf]
	if !valueSet || !subsetSet {
		return nil
	}

	if !utils.ReflectIsSubsetOf(valueV, subsetV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator values '%v' are not all included in the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorValue,
			valueV,
			PolicyOperatorSubsetOf,
			subsetV,
		)
	}
	return nil

}

func policyVerifyValueNotInExcept(p MetadataPolicyEntry, pathInfo string) error {
	valueV, valueSet := p[PolicyOperatorValue]
	exceptV, exceptSet := p[PolicyOperatorExcept]
	if !valueSet || !exceptSet {
		return nil
	}
	if !utils.ReflectDisjoint(valueV, exceptV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator value '%v' is excluded by the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorValue,
			valueV,
			PolicyOperatorExcept,
			exceptV,
		)
	}
	return nil
}

func policyVerifyAddNotInExcept(p MetadataPolicyEntry, pathInfo string) error {
	addV, addSet := p[PolicyOperatorAdd]
	exceptV, exceptSet := p[PolicyOperatorExcept]
	if !addSet || !exceptSet {
		return nil
	}
	if !utils.ReflectDisjoint(addV, exceptV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator value '%v' is excluded by the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorAdd,
			addV,
			PolicyOperatorExcept,
			exceptV,
		)
	}
	return nil
}

func policyVerifySupersetOfNotInExcept(p MetadataPolicyEntry, pathInfo string) error {
	superV, superset := p[PolicyOperatorSupersetOf]
	exceptV, exceptSet := p[PolicyOperatorExcept]
	if !superset || !exceptSet {
		return nil
	}
	if !utils.ReflectDisjoint(superV, exceptV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator value '%v' is excluded by the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorSupersetOf,
			superV,
			PolicyOperatorExcept,
			exceptV,
		)
	}
	return nil
}

func policyVerifyDefaultInSubset(p MetadataPolicyEntry, pathInfo string) error {
	subsetV, subset := p[PolicyOperatorSubsetOf]
	defaultV, defaultSet := p[PolicyOperatorDefault]
	if !subset || !defaultSet {
		return nil
	}
	if !utils.ReflectIsSubsetOf(defaultV, subsetV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator values '%v' are not all included in the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorDefault,
			defaultV,
			PolicyOperatorSubsetOf,
			subsetV,
		)
	}
	return nil
}

func policyVerifyAddInOneOf(p MetadataPolicyEntry, pathInfo string) error {
	oneOfV, oneOf := p[PolicyOperatorOneOf]
	addV, addSet := p[PolicyOperatorAdd]
	if !oneOf || !addSet {
		return nil
	}
	addVs := utils.Slicify(addV)
	if reflect.ValueOf(addVs).Len() > 1 {
		return errors.Errorf(
			"cannot have multiple values in '%s' operator in combination with '%s' operator for '%s' policy",
			PolicyOperatorAdd, PolicyOperatorOneOf, pathInfo,
		)
	}
	if !utils.ReflectSliceContains(reflect.ValueOf(addVs).Index(0).Interface(), oneOfV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator value '%v' is not included in the '%s' operator",
			pathInfo,
			PolicyOperatorAdd,
			addV,
			PolicyOperatorOneOf,
		)
	}
	return nil
}

func policyVerifyDefaultInOneOf(p MetadataPolicyEntry, pathInfo string) error {
	oneOfV, oneOf := p[PolicyOperatorOneOf]
	defaultV, defaultSet := p[PolicyOperatorDefault]
	if !oneOf || !defaultSet {
		return nil
	}
	oneOfVs := utils.Slicify(oneOfV)
	if !utils.ReflectSliceContains(defaultV, oneOfVs) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator value '%v' is not included in the '%s' operator",
			pathInfo,
			PolicyOperatorDefault,
			defaultV,
			PolicyOperatorOneOf,
		)
	}
	return nil
}

func policyVerifyDefaultSuperset(p MetadataPolicyEntry, pathInfo string) error {
	superV, superset := p[PolicyOperatorSupersetOf]
	defaultV, defaultSet := p[PolicyOperatorDefault]
	if !superset || !defaultSet {
		return nil
	}
	if !utils.ReflectIsSupersetOf(defaultV, superV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator values '%v' are not a superset of the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorDefault,
			defaultV,
			PolicyOperatorSupersetOf,
			superV,
		)
	}
	return nil
}

func policyVerifySubsetOfStillHasValues(p MetadataPolicyEntry, pathInfo string) error {
	subsetOf, subsetOfSet := p[PolicyOperatorSubsetOf]
	if !subsetOfSet {
		return nil
	}
	if subsetOf == nil || reflect.ValueOf(utils.Slicify(subsetOf)).Len() == 0 {
		return errors.Errorf(
			"policy_operator '%s' has no valid value after combining policies '%s'",
			PolicyOperatorSubsetOf, pathInfo,
		)
	}
	return nil
}

func policyVerifyOneOfStillHasValues(p MetadataPolicyEntry, pathInfo string) error {
	oneOf, oneOfSet := p[PolicyOperatorOneOf]
	if !oneOfSet {
		return nil
	}
	if oneOf == nil || reflect.ValueOf(utils.Slicify(oneOf)).Len() == 0 {
		return errors.Errorf(
			"policy_operator '%s' has no valid value after combining policies '%s'",
			PolicyOperatorOneOf, pathInfo,
		)
	}
	return nil
}

func init() {
	RegisterPolicyVerifier(policyVerifierSubsetSupersetOneOf)
	RegisterPolicyVerifier(policyVerifierSubsetSupersetOf)
	RegisterPolicyVerifier(policyVerifyAddInSubset)
	RegisterPolicyVerifier(policyVerifyAddInOneOf)
	RegisterPolicyVerifier(policyVerifyAddInValue)
	// RegisterPolicyVerifier(policyVerifyDefaultInOneOf)
	// RegisterPolicyVerifier(policyVerifyDefaultInSubset)
	// RegisterPolicyVerifier(policyVerifyDefaultSuperset)
	// RegisterPolicyVerifier(policyVerifySubsetOfStillHasValues)
	RegisterPolicyVerifier(policyVerifyOneOfStillHasValues)
	RegisterPolicyVerifier(policyVerifySubsetOfAndValue)
	RegisterPolicyVerifier(policyVerifyDefaultAndValue)
	RegisterPolicyVerifier(policyVerifyValueNotInExcept)
	RegisterPolicyVerifier(policyVerifyAddNotInExcept)
	RegisterPolicyVerifier(policyVerifySupersetOfNotInExcept)
}
