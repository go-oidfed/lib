package oidfed

import (
	"testing"

	"github.com/go-oidfed/lib/internal/utils"
)

func TestPolicyOperatorAddMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "both empty slices",
			a:           []string{},
			b:           []string{},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name:        "string + nil",
			a:           "value",
			b:           nil,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "string + empty slice",
			a:           "value",
			b:           []string{},
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:     "string + string",
			a:        "value",
			b:        "other",
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
			},
			errExpected: false,
		},
		{
			name: "string + slice",
			a:    "value",
			b: []string{
				"other",
				"values",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
				"values",
			},
			errExpected: false,
		},
		{
			name: "slice + slice",
			a:    []string{"value"},
			b: []string{
				"other",
				"values",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
				"values",
			},
			errExpected: false,
		},
		{
			name: "slice + slice with duplicates",
			a: []string{
				"value",
				"values",
			},
			b: []string{
				"other",
				"values",
				"value",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"values",
				"other",
			},
			errExpected: false,
		},
		{
			name: "nil + slice",
			a:    nil,
			b: []string{
				"other",
				"values",
				"value",
			},
			pathInfo: "test",
			expected: []string{
				"other",
				"values",
				"value",
			},
			errExpected: false,
		},
		{
			name: "slice + nil",
			a: []string{
				"other",
				"values",
				"value",
			},
			b:        nil,
			pathInfo: "test",
			expected: []string{
				"other",
				"values",
				"value",
			},
			errExpected: false,
		},
		{
			name: "empty slice + slice",
			a:    []string{},
			b: []string{
				"other",
				"values",
				"value",
			},
			pathInfo: "test",
			expected: []string{
				"other",
				"values",
				"value",
			},
			errExpected: false,
		},
		{
			name: "slice + empty slice",
			a: []string{
				"other",
				"values",
				"value",
			},
			b:        []string{},
			pathInfo: "test",
			expected: []string{
				"other",
				"values",
				"value",
			},
			errExpected: false,
		},
	}
	op := policyOperatorAdd
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorAddApply(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		valueSet    bool
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			valueSet:    false,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "value nil, policy string",
			value:       nil,
			valueSet:    false,
			policyValue: "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "value set to nil, policy string",
			value:       nil,
			valueSet:    true,
			policyValue: "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:     "value nil, policy slice",
			value:    nil,
			valueSet: false,
			policyValue: []string{
				"value",
				"other",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
			},
			errExpected: false,
		},
		{
			name:     "value nil, policy slice",
			value:    nil,
			valueSet: true,
			policyValue: []string{
				"value",
				"other",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
			},
			errExpected: false,
		},
		{
			name:        "value string, policy string",
			value:       "value",
			valueSet:    true,
			policyValue: "other",
			pathInfo:    "test",
			expected: []string{
				"value",
				"other",
			},
			errExpected: false,
		},
		{
			name:     "value string, policy slice",
			value:    "value",
			valueSet: true,
			policyValue: []string{
				"additional",
				"other",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"additional",
				"other",
			},
			errExpected: false,
		},
		{
			name:        "value string, policy string dupl",
			value:       "value",
			valueSet:    true,
			policyValue: "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:     "value string, policy slice dupl",
			value:    "value",
			valueSet: true,
			policyValue: []string{
				"value",
				"other",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
			},
			errExpected: false,
		},
		{
			name:        "value empty slice, policy string",
			value:       []string{},
			valueSet:    true,
			policyValue: "value",
			pathInfo:    "test",
			expected:    []string{"value"},
			errExpected: false,
		},
		{
			name:     "value empty slice, policy slice",
			value:    []string{},
			valueSet: true,
			policyValue: []string{
				"value",
				"other",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
			},
			errExpected: false,
		},
		{
			name:        "value slice, policy string",
			value:       []string{"value"},
			valueSet:    true,
			policyValue: "add",
			pathInfo:    "test",
			expected: []string{
				"value",
				"add",
			},
			errExpected: false,
		},
		{
			name: "value slice, policy slice",
			value: []string{
				"value",
				"more",
			},
			valueSet: true,
			policyValue: []string{
				"value",
				"other",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"more",
				"other",
			},
			errExpected: false,
		},
	}
	op := policyOperatorAdd
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, _, err := op.Apply(test.value, test.valueSet, test.policyValue, false, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorSubsetOfMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "both empty",
			a:           []string{},
			b:           []string{},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name: "one nil",
			a:    nil,
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "one empty",
			a:    []string{},
			b: []string{
				"a",
				"b",
			},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name: "equal",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "subset",
			a: []string{
				"a",
				"b",
				"c",
			},
			b: []string{
				"b",
				"c",
				"d",
			},
			pathInfo: "test",
			expected: []string{
				"b",
				"c",
			},
			errExpected: false,
		},
		{
			name: "distinct",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"c",
				"d",
			},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
	}
	op := policyOperatorSubsetOf
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorSubsetOfApply(t *testing.T) {
	tests := []struct {
		name        string
		essential   bool
		value       any
		valueSet    bool
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			valueSet:    false,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "both nil essential",
			essential:   true,
			value:       nil,
			valueSet:    false,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:     "value nil",
			value:    nil,
			valueSet: false,
			policyValue: []string{
				"a",
				"b",
			},
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:      "value nil essential",
			essential: true,
			value:     nil,
			valueSet:  false,
			policyValue: []string{
				"a",
				"b",
			},
			pathInfo:    "test",
			expected:    nil,
			errExpected: true,
		},
		{
			name: "policy nil",
			value: []string{
				"a",
				"b",
			},
			valueSet:    true,
			policyValue: nil,
			pathInfo:    "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name:      "policy nil essential",
			essential: true,
			value: []string{
				"a",
				"b",
			},
			valueSet:    true,
			policyValue: nil,
			pathInfo:    "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "equal",
			value: []string{
				"a",
				"b",
			},
			valueSet: true,
			policyValue: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "subset",
			value: []string{
				"a",
				"b",
			},
			valueSet: true,
			policyValue: []string{
				"a",
				"b",
				"c",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "no subset",
			value: []string{
				"a",
				"c",
				"d",
			},
			valueSet: true,
			policyValue: []string{
				"a",
				"b",
				"c",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"c",
			},
			errExpected: false,
		},
		{
			name: "distinct",
			value: []string{
				"a",
				"b",
			},
			valueSet: true,
			policyValue: []string{
				"c",
				"d",
			},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name:      "distinct essential",
			essential: true,
			value: []string{
				"a",
				"b",
			},
			valueSet: true,
			policyValue: []string{
				"c",
				"d",
			},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
	}
	op := policyOperatorSubsetOf
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, _, err := op.Apply(
					test.value,
					test.valueSet, test.policyValue, test.essential,
					test.pathInfo,
				)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorOneOfMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name: "a nil",
			a: []string{
				"a",
				"b",
			},
			b:        nil,
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "b nil",
			a:    nil,
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name:        "both empty",
			a:           []string{},
			b:           []string{},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name: "one empty",
			a: []string{
				"a",
				"b",
			},
			b:           []string{},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name: "distinct",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"c",
				"d",
			},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name: "equal",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "intersect",
			a: []string{
				"a",
				"b",
				"c",
			},
			b: []string{
				"b",
				"c",
				"d",
			},
			pathInfo: "test",
			expected: []string{
				"b",
				"c",
			},
			errExpected: false,
		},
		{
			name: "subset",
			a: []string{
				"a",
				"b",
				"c",
			},
			b: []string{
				"b",
				"c",
			},
			pathInfo: "test",
			expected: []string{
				"b",
				"c",
			},
			errExpected: false,
		},
		{
			name: "only one left",
			a: []string{
				"a",
				"b",
				"c",
			},
			b: []string{
				"b",
				"d",
			},
			pathInfo:    "test",
			expected:    []string{"b"},
			errExpected: false,
		},
	}
	op := policyOperatorOneOf
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorOneOfApply(t *testing.T) {
	tests := []struct {
		name        string
		essential   bool
		value       any
		valueSet    bool
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			valueSet:    false,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "both nil",
			essential:   true,
			value:       nil,
			valueSet:    false,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "policy nil",
			value:       "value",
			valueSet:    true,
			policyValue: nil,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "policy nil; essential",
			essential:   true,
			value:       "value",
			valueSet:    true,
			policyValue: nil,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:     "value nil",
			value:    nil,
			valueSet: false,
			policyValue: []string{
				"a",
				"b",
			},
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:      "value nil; essential",
			value:     nil,
			valueSet:  false,
			essential: true,
			policyValue: []string{
				"a",
				"b",
			},
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name:     "one of",
			value:    "value",
			valueSet: true,
			policyValue: []string{
				"one",
				"of",
				"value",
			},
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:     "not one of",
			value:    "other",
			valueSet: true,
			policyValue: []string{
				"one",
				"of",
				"value",
			},
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name: "slice as value",
			value: []string{
				"one",
				"of",
				"value",
			},
			valueSet: true,
			policyValue: []string{
				"one",
				"of",
				"value",
			},
			pathInfo:    "test",
			errExpected: true,
		},
	}
	op := policyOperatorOneOf
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, _, err := op.Apply(
					test.value,
					test.valueSet, test.policyValue, test.essential,
					test.pathInfo,
				)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorSupersetOfMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name: "a nil",
			a:    nil,
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "b nil",
			a: []string{
				"a",
				"b",
			},
			b:        nil,
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "a empty",
			a:    []string{},
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "b empty",
			a: []string{
				"a",
				"b",
			},
			b:        []string{},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "equal",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "distinct",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"c",
				"d",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
				"c",
				"d",
			},
			errExpected: false,
		},
		{
			name: "mixed",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"b",
				"c",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
				"c",
			},
			errExpected: false,
		},
	}
	op := policyOperatorSupersetOf
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorSupersetOfApply(t *testing.T) {
	tests := []struct {
		name        string
		essential   bool
		value       any
		valueSet    bool
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			valueSet:    false,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "both nil; essential",
			essential:   true,
			value:       nil,
			valueSet:    false,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name: "policy nil",
			value: []string{
				"a",
				"b",
			},
			valueSet:    true,
			policyValue: nil,
			pathInfo:    "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "policy nil; essential",
			value: []string{
				"a",
				"b",
			},
			valueSet:    true,
			policyValue: nil,
			pathInfo:    "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "policy empty",
			value: []string{
				"a",
				"b",
			},
			valueSet:    true,
			policyValue: []string{},
			pathInfo:    "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name:        "value nil",
			value:       nil,
			valueSet:    false,
			policyValue: []string{"a"},
			pathInfo:    "test",
			errExpected: false,
		},
		{
			name:        "value nil; essential",
			essential:   true,
			value:       nil,
			valueSet:    false,
			policyValue: []string{"a"},
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name:        "value empty",
			value:       []string{},
			valueSet:    true,
			policyValue: []string{"a"},
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name:        "value empty; essential",
			essential:   true,
			value:       []string{},
			valueSet:    true,
			policyValue: []string{"a"},
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name: "equal",
			value: []string{
				"a",
				"b",
			},
			valueSet: true,
			policyValue: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "superset",
			value: []string{
				"a",
				"b",
			},
			valueSet:    true,
			policyValue: []string{"a"},
			pathInfo:    "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "no superset",
			value: []string{
				"a",
				"b",
			},
			valueSet: true,
			policyValue: []string{
				"a",
				"c",
			},
			pathInfo:    "test",
			errExpected: true,
		},
	}
	op := policyOperatorSupersetOf
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, _, err := op.Apply(
					test.value,
					test.valueSet, test.policyValue, test.essential,
					test.pathInfo,
				)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly: %v", err)
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorValueMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "a nil",
			a:           nil,
			b:           "value",
			pathInfo:    "test",
			expected:    nil,
			errExpected: true,
		},
		{
			name:        "b nil",
			a:           "value",
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: true,
		},
		{
			name:        "equal string",
			a:           "value",
			b:           "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "different string",
			a:           "value",
			b:           "value2",
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name: "equal slices",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "equal slices wrong order",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"b",
				"a",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "different slices",
			a: []string{
				"a",
				"b",
				"c",
			},
			b: []string{
				"b",
				"a",
			},
			pathInfo:    "test",
			errExpected: true,
		},
	}
	op := policyOperatorValue
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorValueApply(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		valueSet    bool
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			valueSet:    false,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "policy nil",
			value:       "value",
			valueSet:    true,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "policy string",
			value:       "value",
			valueSet:    true,
			policyValue: "overwrite",
			pathInfo:    "test",
			expected:    "overwrite",
			errExpected: false,
		},
		{
			name:     "policy slice string",
			value:    "value",
			valueSet: true,
			policyValue: []string{
				"overwrite",
				"with",
				"values",
			},
			pathInfo: "test",
			expected: []string{
				"overwrite",
				"with",
				"values",
			},
			errExpected: false,
		},
	}
	op := policyOperatorValue
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, _, err := op.Apply(test.value, test.valueSet, test.policyValue, false, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorDefaultMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "a nil",
			a:           nil,
			b:           "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "b nil",
			a:           "value",
			b:           nil,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "equal string",
			a:           "value",
			b:           "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "different string",
			a:           "value",
			b:           "value2",
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name: "equal slices",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "equal slices wrong order",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"b",
				"a",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "different slices",
			a: []string{
				"a",
				"b",
				"c",
			},
			b: []string{
				"b",
				"a",
			},
			pathInfo:    "test",
			errExpected: true,
		},
	}
	op := policyOperatorDefault
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorDefaultApply(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		valueSet    bool
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			valueSet:    false,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "policy nil",
			value:       "value",
			valueSet:    true,
			policyValue: nil,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "value nil",
			value:       nil,
			valueSet:    false,
			policyValue: "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "value empty string set",
			value:       "",
			valueSet:    true,
			policyValue: "value",
			pathInfo:    "test",
			expected:    "",
			errExpected: false,
		},
		{
			name:        "value empty struct set",
			value:       struct{}{},
			valueSet:    true,
			policyValue: "value",
			pathInfo:    "test",
			expected:    struct{}{},
			errExpected: false,
		},
		{
			name:        "value empty string",
			value:       "",
			valueSet:    false,
			policyValue: "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "value empty struct",
			value:       struct{}{},
			valueSet:    false,
			policyValue: "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "policy string",
			value:       "value",
			valueSet:    true,
			policyValue: "default",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:     "policy slice string",
			value:    "value",
			valueSet: true,
			policyValue: []string{
				"default",
				"with",
				"values",
			},
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
	}
	op := policyOperatorDefault
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, _, err := op.Apply(
					test.value,
					test.valueSet, test.policyValue, false, test.pathInfo,
				)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorEssentialMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    false,
			errExpected: false,
		},
		{
			name:        "nil + false",
			a:           nil,
			b:           false,
			pathInfo:    "test",
			expected:    false,
			errExpected: false,
		},
		{
			name:        "false + nil",
			a:           false,
			b:           nil,
			pathInfo:    "test",
			expected:    false,
			errExpected: false,
		},
		{
			name:        "nil + true",
			a:           nil,
			b:           true,
			pathInfo:    "test",
			expected:    true,
			errExpected: false,
		},
		{
			name:        "true + nil",
			a:           true,
			b:           nil,
			pathInfo:    "test",
			expected:    true,
			errExpected: false,
		},
		{
			name:        "false + true",
			a:           false,
			b:           true,
			pathInfo:    "test",
			expected:    true,
			errExpected: false,
		},
		{
			name:        "true + false",
			a:           true,
			b:           false,
			pathInfo:    "test",
			expected:    true,
			errExpected: false,
		},
		{
			name:        "true + true",
			a:           true,
			b:           true,
			pathInfo:    "test",
			expected:    true,
			errExpected: false,
		},
		{
			name:        "false + false",
			a:           false,
			b:           false,
			pathInfo:    "test",
			expected:    false,
			errExpected: false,
		},
	}
	op := policyOperatorEssential
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorEssentialApply(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		valueSet    bool
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			valueSet:    false,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "value nil + false",
			value:       nil,
			valueSet:    false,
			policyValue: false,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "value nil + true",
			value:       nil,
			valueSet:    false,
			policyValue: true,
			pathInfo:    "test",
			expected:    nil,
			errExpected: true,
		},
		{
			name:        "value empty string + true",
			value:       "",
			valueSet:    true,
			policyValue: true,
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name:        "value empty struct + true",
			value:       struct{}{},
			valueSet:    true,
			policyValue: true,
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name:        "value string + true",
			value:       "value",
			valueSet:    true,
			policyValue: true,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "value empty string + false",
			value:       "",
			valueSet:    true,
			policyValue: false,
			pathInfo:    "test",
			expected:    "",
			errExpected: false,
		},
		{
			name:        "value empty struct + false",
			value:       struct{}{},
			valueSet:    true,
			policyValue: false,
			pathInfo:    "test",
			expected:    struct{}{},
			errExpected: false,
		},
		{
			name:        "value string + false",
			value:       "value",
			valueSet:    true,
			policyValue: false,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
	}
	op := policyOperatorEssential
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, _, err := op.Apply(
					test.value,
					test.valueSet, test.policyValue, false, test.pathInfo,
				)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorExceptMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "a nil",
			a:           nil,
			b:           []string{"a", "b"},
			pathInfo:    "test",
			expected:    []string{"a", "b"},
			errExpected: false,
		},
		{
			name:        "b nil",
			a:           []string{"a", "b"},
			b:           nil,
			pathInfo:    "test",
			expected:    []string{"a", "b"},
			errExpected: false,
		},
		{
			name:        "both empty",
			a:           []string{},
			b:           []string{},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name:        "disjoint (union)",
			a:           []string{"a", "b"},
			b:           []string{"c", "d"},
			pathInfo:    "test",
			expected:    []string{"a", "b", "c", "d"},
			errExpected: false,
		},
		{
			name:        "overlapping (union, no duplicates)",
			a:           []string{"a", "b"},
			b:           []string{"b", "c"},
			pathInfo:    "test",
			expected:    []string{"a", "b", "c"},
			errExpected: false,
		},
	}
	op := policyOperatorExcept
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorExceptApply(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		valueSet    bool
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "value not set",
			value:       nil,
			valueSet:    false,
			policyValue: []string{"a"},
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "policy nil",
			value:       []string{"a", "b"},
			valueSet:    true,
			policyValue: nil,
			pathInfo:    "test",
			expected:    []string{"a", "b"},
			errExpected: false,
		},
		{
			name:        "multi-valued removal partial",
			value:       []string{"RS256", "RS512", "ES256", "ES512"},
			valueSet:    true,
			policyValue: []string{"RS256", "RS384"},
			pathInfo:    "test",
			expected:    []string{"RS512", "ES256", "ES512"},
			errExpected: false,
		},
		{
			name:        "multi-valued removal all (empty result)",
			value:       []string{"RS256", "RS384"},
			valueSet:    true,
			policyValue: []string{"RS256", "RS384"},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name:        "multi-valued removal none present (silently ignored)",
			value:       []string{"RS512", "ES256"},
			valueSet:    true,
			policyValue: []string{"RS256", "RS384"},
			pathInfo:    "test",
			expected:    []string{"RS512", "ES256"},
			errExpected: false,
		},
		{
			name:        "single-valued not excluded (passthrough)",
			value:       "RS512",
			valueSet:    true,
			policyValue: []string{"RS256", "RS384"},
			pathInfo:    "test",
			expected:    "RS512",
			errExpected: false,
		},
		{
			name:        "single-valued excluded (error)",
			value:       "client_secret_basic",
			valueSet:    true,
			policyValue: []string{"client_secret_basic"},
			pathInfo:    "test",
			errExpected: true,
		},
	}
	op := policyOperatorExcept
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, _, err := op.Apply(test.value, test.valueSet, test.policyValue, false, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}
