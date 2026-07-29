package oidfed

import (
	"testing"
)

func TestPolicyVerifierSubsetSupersetOneOf(t *testing.T) {
	tests := []struct {
		name        string
		pathInfo    string
		policy      MetadataPolicyEntry
		errExpected bool
	}{
		{
			name:        "nil",
			pathInfo:    "test",
			policy:      nil,
			errExpected: false,
		},
		{
			name:        "all empty",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{},
			errExpected: false,
		},
		{
			name:     "only subset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: []string{
					"one",
					"two",
				},
			},
			errExpected: false,
		},
		{
			name:     "only superset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSupersetOf: []string{
					"one",
					"two",
				},
			},
			errExpected: false,
		},
		{
			name:     "only oneof",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorOneOf: []string{
					"one",
					"two",
				},
			},
			errExpected: false,
		},
		{
			name:     "subset + superset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: []string{
					"one",
					"two",
				},
				PolicyOperatorSupersetOf: []string{"one"},
			},
			errExpected: false,
		},
		{
			name:     "subset + superset + oneof",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: []string{
					"one",
					"two",
				},
				PolicyOperatorSupersetOf: []string{"one"},
				PolicyOperatorOneOf: []string{
					"one",
					"two",
				},
			},
			errExpected: true,
		},
		{
			name:     "subset + oneof",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: []string{
					"one",
					"two",
				},
				PolicyOperatorOneOf: []string{
					"one",
					"two",
				},
			},
			errExpected: true,
		},
		{
			name:     "superset + oneof",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSupersetOf: []string{"one"},
				PolicyOperatorOneOf: []string{
					"one",
					"two",
				},
			},
			errExpected: true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if err := policyVerifierSubsetSupersetOneOf(
					test.policy, test.pathInfo,
				); err != nil != test.errExpected {
					if test.errExpected {
						t.Errorf("expected error, but verified correctly")
					} else {
						t.Errorf("did not expect error, but did not verify correctly")
					}
				}
			},
		)
	}
}

func TestPolicyVerifierSubsetSupersetOf(t *testing.T) {
	tests := []struct {
		name        string
		pathInfo    string
		policy      MetadataPolicyEntry
		errExpected bool
	}{
		{
			name:        "nil",
			pathInfo:    "test",
			policy:      nil,
			errExpected: false,
		},
		{
			name:        "all empty",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{},
			errExpected: false,
		},
		{
			name:     "only subset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: []string{
					"one",
					"of",
					"three",
				},
			},
			errExpected: false,
		},
		{
			name:     "only superset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSupersetOf: []string{
					"one",
					"two",
				},
			},
			errExpected: false,
		},
		{
			name:     "superset is subset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: []string{
					"one",
					"two",
					"three",
				},
				PolicyOperatorSupersetOf: []string{
					"one",
					"two",
				},
			},
			errExpected: false,
		},
		{
			name:     "subset is completely different",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: []string{
					"all",
					"are",
					"different",
				},
				PolicyOperatorSupersetOf: []string{
					"one",
					"two",
				},
			},
			errExpected: true,
		},
		{
			name:     "subset is not superset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: []string{
					"one",
					"of",
					"three",
				},
				PolicyOperatorSupersetOf: []string{
					"one",
					"two",
				},
			},
			errExpected: true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if err := policyVerifierSubsetSupersetOf(
					test.policy, test.pathInfo,
				); err != nil != test.errExpected {
					if test.errExpected {
						t.Errorf("expected error, but verified correctly")
					} else {
						t.Errorf("did not expect error, but did not verify correctly: %v", err)
					}
				}
			},
		)
	}
}

func TestPolicyVerifyAddInSubset(t *testing.T) {
	tests := []struct {
		name        string
		pathInfo    string
		policy      MetadataPolicyEntry
		errExpected bool
	}{
		{
			name:        "nil",
			pathInfo:    "test",
			policy:      nil,
			errExpected: false,
		},
		{
			name:        "all empty",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{},
			errExpected: false,
		},
		{
			name:     "only add",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd: "value",
			},
			errExpected: false,
		},
		{
			name:     "only subset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "single value subset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd: "value",
				PolicyOperatorSubsetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "multiple value subset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd: []string{
					"value",
					"other",
				},
				PolicyOperatorSubsetOf: []string{
					"value",
					"more",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "equal",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd: []string{
					"value",
					"other",
				},
				PolicyOperatorSubsetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "no subset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd: []string{
					"value",
					"different",
				},
				PolicyOperatorSubsetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: true,
		},
		{
			name:     "single value not included",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd: "different",
				PolicyOperatorSubsetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if err := policyVerifyAddInSubset(
					test.policy, test.pathInfo,
				); err != nil != test.errExpected {
					if test.errExpected {
						t.Errorf("expected error, but verified correctly")
					} else {
						t.Errorf("did not expect error, but did not verify correctly: %v", err)
					}
				}
			},
		)
	}
}

func TestPolicyVerifyAddInOneOf(t *testing.T) {
	tests := []struct {
		name        string
		pathInfo    string
		policy      MetadataPolicyEntry
		errExpected bool
	}{
		{
			name:        "nil",
			pathInfo:    "test",
			policy:      nil,
			errExpected: false,
		},
		{
			name:        "all empty",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{},
			errExpected: false,
		},
		{
			name:     "only add",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd: "value",
			},
			errExpected: false,
		},
		{
			name:     "only oneof",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorOneOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "single value",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd: "value",
				PolicyOperatorOneOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "multiple values",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd: []string{
					"value",
					"other",
				},
				PolicyOperatorOneOf: []string{
					"value",
					"more",
					"other",
				},
			},
			errExpected: true,
		},
		{
			name:     "equal with slice in add",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd: []string{
					"value",
				},
				PolicyOperatorOneOf: []string{
					"value",
				},
			},
			errExpected: false,
		},
		{
			name:     "equal",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd: "value",
				PolicyOperatorOneOf: []string{
					"value",
				},
			},
			errExpected: false,
		},
		{
			name:     "not included",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd: "different",
				PolicyOperatorOneOf: []string{
					"value",
					"other",
				},
			},
			errExpected: true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if err := policyVerifyAddInOneOf(
					test.policy, test.pathInfo,
				); err != nil != test.errExpected {
					if test.errExpected {
						t.Errorf("expected error, but verified correctly")
					} else {
						t.Errorf("did not expect error, but did not verify correctly")
					}
				}
			},
		)
	}
}

func TestPolicyVerifyDefaultInOneOf(t *testing.T) {
	tests := []struct {
		name        string
		pathInfo    string
		policy      MetadataPolicyEntry
		errExpected bool
	}{
		{
			name:        "nil",
			pathInfo:    "test",
			policy:      nil,
			errExpected: false,
		},
		{
			name:        "all empty",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{},
			errExpected: false,
		},
		{
			name:     "only default",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: "value",
			},
			errExpected: false,
		},
		{
			name:     "only oneof",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorOneOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "single value",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: "value",
				PolicyOperatorOneOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "multiple values",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: []string{
					"value",
					"other",
				},
				PolicyOperatorOneOf: []string{
					"value",
					"more",
					"other",
				},
			},
			errExpected: true,
		},
		{
			name:     "equal with slice in default",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: []string{
					"value",
				},
				PolicyOperatorOneOf: []string{
					"value",
				},
			},
			errExpected: true,
		},
		{
			name:     "equal",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: "value",
				PolicyOperatorOneOf: []string{
					"value",
				},
			},
			errExpected: false,
		},
		{
			name:     "not included",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: "different",
				PolicyOperatorOneOf: []string{
					"value",
					"other",
				},
			},
			errExpected: true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if err := policyVerifyDefaultInOneOf(
					test.policy, test.pathInfo,
				); err != nil != test.errExpected {
					if test.errExpected {
						t.Errorf("expected error, but verified correctly")
					} else {
						t.Errorf("did not expect error, but did not verify correctly")
					}
				}
			},
		)
	}
}

func TestPolicyVerifyDefaultInSubset(t *testing.T) {
	tests := []struct {
		name        string
		pathInfo    string
		policy      MetadataPolicyEntry
		errExpected bool
	}{
		{
			name:        "nil",
			pathInfo:    "test",
			policy:      nil,
			errExpected: false,
		},
		{
			name:        "all empty",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{},
			errExpected: false,
		},
		{
			name:     "only default",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: "value",
			},
			errExpected: false,
		},
		{
			name:     "only subset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "single value subset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: "value",
				PolicyOperatorSubsetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "multiple value subset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: []string{
					"value",
					"other",
				},
				PolicyOperatorSubsetOf: []string{
					"value",
					"more",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "equal",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: []string{
					"value",
					"other",
				},
				PolicyOperatorSubsetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "no subset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: []string{
					"value",
					"different",
				},
				PolicyOperatorSubsetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: true,
		},
		{
			name:     "single value not included",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: "different",
				PolicyOperatorSubsetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if err := policyVerifyDefaultInSubset(
					test.policy, test.pathInfo,
				); err != nil != test.errExpected {
					if test.errExpected {
						t.Errorf("expected error, but verified correctly")
					} else {
						t.Errorf("did not expect error, but did not verify correctly: %v", err)
					}
				}
			},
		)
	}
}

func TestPolicyVerifyDefaultSuperset(t *testing.T) {
	tests := []struct {
		name        string
		pathInfo    string
		policy      MetadataPolicyEntry
		errExpected bool
	}{
		{
			name:        "nil",
			pathInfo:    "test",
			policy:      nil,
			errExpected: false,
		},
		{
			name:        "all empty",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{},
			errExpected: false,
		},
		{
			name:     "only default",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: "value",
			},
			errExpected: false,
		},
		{
			name:     "only superset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSupersetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "single value",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: "value",
				PolicyOperatorSupersetOf: []string{
					"value",
				},
			},
			errExpected: false,
		},
		{
			name:     "multiple value",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: []string{
					"value",
					"more",
					"other",
				},
				PolicyOperatorSupersetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "equal",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: []string{
					"value",
					"other",
				},
				PolicyOperatorSupersetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: false,
		},
		{
			name:     "no superset",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: []string{
					"value",
					"different",
				},
				PolicyOperatorSupersetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: true,
		},
		{
			name:     "single value not included",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorDefault: "different",
				PolicyOperatorSupersetOf: []string{
					"value",
					"other",
				},
			},
			errExpected: true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if err := policyVerifyDefaultSuperset(
					test.policy, test.pathInfo,
				); err != nil != test.errExpected {
					if test.errExpected {
						t.Errorf("expected error, but verified correctly")
					} else {
						t.Errorf("did not expect error, but did not verify correctly: %v", err)
					}
				}
			},
		)
	}
}

func TestPolicyVerifierPolicyVerifyOneOfStillHasValues(t *testing.T) {
	tests := []struct {
		name        string
		pathInfo    string
		policy      MetadataPolicyEntry
		errExpected bool
	}{
		{
			name:        "nil",
			pathInfo:    "test",
			policy:      nil,
			errExpected: false,
		},
		{
			name:        "all empty",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{},
			errExpected: false,
		},
		{
			name:     "one of nil",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorOneOf: nil,
			},
			errExpected: true,
		},
		{
			name:     "one of empty",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorOneOf: []string{},
			},
			errExpected: true,
		},
		{
			name:     "values",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorOneOf: []string{
					"one",
					"two",
				},
			},
			errExpected: false,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if err := policyVerifyOneOfStillHasValues(
					test.policy, test.pathInfo,
				); err != nil != test.errExpected {
					if test.errExpected {
						t.Errorf("expected error, but verified correctly")
					} else {
						t.Errorf("did not expect error, but did not verify correctly")
					}
				}
			},
		)
	}
}

func TestPolicyVerifierPolicyVerifySubsetOfStillHasValues(t *testing.T) {
	tests := []struct {
		name        string
		pathInfo    string
		policy      MetadataPolicyEntry
		errExpected bool
	}{
		{
			name:        "nil",
			pathInfo:    "test",
			policy:      nil,
			errExpected: false,
		},
		{
			name:        "all empty",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{},
			errExpected: false,
		},
		{
			name:     "subset nil",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: nil,
			},
			errExpected: true,
		},
		{
			name:     "subset empty",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: []string{},
			},
			errExpected: true,
		},
		{
			name:     "values",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSubsetOf: []string{
					"one",
					"two",
				},
			},
			errExpected: false,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if err := policyVerifySubsetOfStillHasValues(
					test.policy, test.pathInfo,
				); err != nil != test.errExpected {
					if test.errExpected {
						t.Errorf("expected error, but verified correctly")
					} else {
						t.Errorf("did not expect error, but did not verify correctly")
					}
				}
			},
		)
	}
}

func TestPolicyVerifyValueNotInExcept(t *testing.T) {
	tests := []struct {
		name        string
		pathInfo    string
		policy      MetadataPolicyEntry
		errExpected bool
	}{
		{
			name:        "no except",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{PolicyOperatorValue: "a"},
			errExpected: false,
		},
		{
			name:        "no value",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{PolicyOperatorExcept: []string{"a"}},
			errExpected: false,
		},
		{
			name:     "disjoint",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorValue:  "a",
				PolicyOperatorExcept: []string{"b", "c"},
			},
			errExpected: false,
		},
		{
			name:     "value slice disjoint",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorValue:  []string{"a", "b"},
				PolicyOperatorExcept: []string{"c", "d"},
			},
			errExpected: false,
		},
		{
			name:     "value conflicts",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorValue:  "client_secret_basic",
				PolicyOperatorExcept: []string{"client_secret_basic"},
			},
			errExpected: true,
		},
		{
			name:     "value slice conflicts",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorValue:  []string{"a", "b"},
				PolicyOperatorExcept: []string{"b"},
			},
			errExpected: true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if err := policyVerifyValueNotInExcept(
					test.policy, test.pathInfo,
				); err != nil != test.errExpected {
					if test.errExpected {
						t.Errorf("expected error, but verified correctly")
					} else {
						t.Errorf("did not expect error, but did not verify correctly")
					}
				}
			},
		)
	}
}

func TestPolicyVerifyAddNotInExcept(t *testing.T) {
	tests := []struct {
		name        string
		pathInfo    string
		policy      MetadataPolicyEntry
		errExpected bool
	}{
		{
			name:        "no except",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{PolicyOperatorAdd: []string{"a"}},
			errExpected: false,
		},
		{
			name:        "no add",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{PolicyOperatorExcept: []string{"a"}},
			errExpected: false,
		},
		{
			name:     "disjoint",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd:    []string{"a", "b"},
				PolicyOperatorExcept: []string{"c"},
			},
			errExpected: false,
		},
		{
			name:     "conflict",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorAdd:    []string{"a", "b"},
				PolicyOperatorExcept: []string{"b"},
			},
			errExpected: true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if err := policyVerifyAddNotInExcept(
					test.policy, test.pathInfo,
				); err != nil != test.errExpected {
					if test.errExpected {
						t.Errorf("expected error, but verified correctly")
					} else {
						t.Errorf("did not expect error, but did not verify correctly")
					}
				}
			},
		)
	}
}

func TestPolicyVerifySupersetOfNotInExcept(t *testing.T) {
	tests := []struct {
		name        string
		pathInfo    string
		policy      MetadataPolicyEntry
		errExpected bool
	}{
		{
			name:        "no except",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{PolicyOperatorSupersetOf: []string{"a"}},
			errExpected: false,
		},
		{
			name:        "no superset",
			pathInfo:    "test",
			policy:      MetadataPolicyEntry{PolicyOperatorExcept: []string{"a"}},
			errExpected: false,
		},
		{
			name:     "disjoint",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSupersetOf: []string{"a", "b"},
				PolicyOperatorExcept:     []string{"c"},
			},
			errExpected: false,
		},
		{
			name:     "conflict",
			pathInfo: "test",
			policy: MetadataPolicyEntry{
				PolicyOperatorSupersetOf: []string{"a", "b"},
				PolicyOperatorExcept:     []string{"b"},
			},
			errExpected: true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				if err := policyVerifySupersetOfNotInExcept(
					test.policy, test.pathInfo,
				); err != nil != test.errExpected {
					if test.errExpected {
						t.Errorf("expected error, but verified correctly")
					} else {
						t.Errorf("did not expect error, but did not verify correctly")
					}
				}
			},
		)
	}
}
