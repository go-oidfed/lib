package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected bool
	}{
		{"string slice", []string{"a", "b"}, true},
		{"int slice", []int{1, 2, 3}, true},
		{"empty slice", []string{}, true},
		{"interface slice", []any{1, "a"}, true},
		{"string", "not a slice", false},
		{"int", 42, false},
		{"struct", struct{}{}, false},
		{"map", map[string]int{}, false},
		{"nil slice", ([]string)(nil), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSlice(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSlice_Nil(t *testing.T) {
	// nil interface requires special handling
	var nilInterface any
	assert.False(t, IsSlice(nilInterface))
}

func TestSlicify(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		result := Slicify(nil)
		assert.Nil(t, result)
	})

	t.Run("slice returns slice", func(t *testing.T) {
		input := []string{"a", "b"}
		result := Slicify(input)
		assert.Equal(t, input, result)
	})

	t.Run("string becomes string slice", func(t *testing.T) {
		result := Slicify("hello")
		assert.Equal(t, []string{"hello"}, result)
	})

	t.Run("int becomes int slice", func(t *testing.T) {
		result := Slicify(42)
		assert.Equal(t, []int{42}, result)
	})

	t.Run("struct becomes struct slice", func(t *testing.T) {
		type testStruct struct{ Value int }
		input := testStruct{Value: 1}
		result := Slicify(input)
		expected := []testStruct{{Value: 1}}
		assert.Equal(t, expected, result)
	})
}

func TestReflectSliceContains(t *testing.T) {
	t.Run("non-slice returns false", func(t *testing.T) {
		assert.False(t, ReflectSliceContains("a", "not a slice"))
	})

	t.Run("empty slice returns false", func(t *testing.T) {
		assert.False(t, ReflectSliceContains("a", []string{}))
	})

	t.Run("string slice contains element", func(t *testing.T) {
		slice := []string{"a", "b", "c"}
		assert.True(t, ReflectSliceContains("b", slice))
	})

	t.Run("string slice does not contain element", func(t *testing.T) {
		slice := []string{"a", "b", "c"}
		assert.False(t, ReflectSliceContains("d", slice))
	})

	t.Run("int slice contains element", func(t *testing.T) {
		slice := []int{1, 2, 3}
		assert.True(t, ReflectSliceContains(2, slice))
	})

	t.Run("int slice does not contain element", func(t *testing.T) {
		slice := []int{1, 2, 3}
		assert.False(t, ReflectSliceContains(4, slice))
	})

	t.Run("interface slice contains element", func(t *testing.T) {
		slice := []any{1, "a", true}
		assert.True(t, ReflectSliceContains("a", slice))
	})
}

func TestReflectSliceCast(t *testing.T) {
	t.Run("non-slice returns original", func(t *testing.T) {
		result := ReflectSliceCast("not a slice", []string{})
		assert.Equal(t, "not a slice", result)
	})

	t.Run("empty slice", func(t *testing.T) {
		result := ReflectSliceCast([]any{}, []string{})
		assert.Equal(t, []string{}, result)
	})

	t.Run("interface to string slice", func(t *testing.T) {
		input := []any{"a", "b", "c"}
		result := ReflectSliceCast(input, []string{})
		assert.Equal(t, []string{"a", "b", "c"}, result)
	})

	t.Run("interface to int slice", func(t *testing.T) {
		input := []any{1, 2, 3}
		result := ReflectSliceCast(input, []int{})
		assert.Equal(t, []int{1, 2, 3}, result)
	})

	t.Run("cast to interface slice", func(t *testing.T) {
		input := []string{"a", "b"}
		result := ReflectSliceCast(input, []any{})
		// When target is interface, values are kept as-is
		assert.Len(t, result.([]any), 2)
	})
}

func TestConvertToTargetType_Primitives(t *testing.T) {
	// Test through ReflectSliceCast which uses convertToTargetType internally
	t.Run("bool", func(t *testing.T) {
		input := []any{true, false}
		result := ReflectSliceCast(input, []bool{})
		assert.Equal(t, []bool{true, false}, result)
	})

	t.Run("int", func(t *testing.T) {
		input := []any{1, 2, 3}
		result := ReflectSliceCast(input, []int{})
		assert.Equal(t, []int{1, 2, 3}, result)
	})

	t.Run("int8", func(t *testing.T) {
		input := []any{int8(1), int8(2)}
		result := ReflectSliceCast(input, []int8{})
		assert.Equal(t, []int8{1, 2}, result)
	})

	t.Run("int16", func(t *testing.T) {
		input := []any{int16(1), int16(2)}
		result := ReflectSliceCast(input, []int16{})
		assert.Equal(t, []int16{1, 2}, result)
	})

	t.Run("int32", func(t *testing.T) {
		input := []any{int32(1), int32(2)}
		result := ReflectSliceCast(input, []int32{})
		assert.Equal(t, []int32{1, 2}, result)
	})

	t.Run("int64", func(t *testing.T) {
		input := []any{int64(1), int64(2)}
		result := ReflectSliceCast(input, []int64{})
		assert.Equal(t, []int64{1, 2}, result)
	})

	t.Run("uint", func(t *testing.T) {
		input := []any{uint(1), uint(2)}
		result := ReflectSliceCast(input, []uint{})
		assert.Equal(t, []uint{1, 2}, result)
	})

	t.Run("uint8", func(t *testing.T) {
		input := []any{uint8(1), uint8(2)}
		result := ReflectSliceCast(input, []uint8{})
		assert.Equal(t, []uint8{1, 2}, result)
	})

	t.Run("uint16", func(t *testing.T) {
		input := []any{uint16(1), uint16(2)}
		result := ReflectSliceCast(input, []uint16{})
		assert.Equal(t, []uint16{1, 2}, result)
	})

	t.Run("uint32", func(t *testing.T) {
		input := []any{uint32(1), uint32(2)}
		result := ReflectSliceCast(input, []uint32{})
		assert.Equal(t, []uint32{1, 2}, result)
	})

	t.Run("uint64", func(t *testing.T) {
		input := []any{uint64(1), uint64(2)}
		result := ReflectSliceCast(input, []uint64{})
		assert.Equal(t, []uint64{1, 2}, result)
	})

	t.Run("float32", func(t *testing.T) {
		input := []any{float32(1.5), float32(2.5)}
		result := ReflectSliceCast(input, []float32{})
		assert.Equal(t, []float32{1.5, 2.5}, result)
	})

	t.Run("float64", func(t *testing.T) {
		input := []any{1.5, 2.5}
		result := ReflectSliceCast(input, []float64{})
		assert.Equal(t, []float64{1.5, 2.5}, result)
	})

	t.Run("string", func(t *testing.T) {
		input := []any{"hello", "world"}
		result := ReflectSliceCast(input, []string{})
		assert.Equal(t, []string{"hello", "world"}, result)
	})
}

func TestReflectUnion(t *testing.T) {
	t.Run("both empty", func(t *testing.T) {
		result := ReflectUnion([]string{}, []string{})
		assert.Equal(t, []string{}, result)
	})

	t.Run("first empty", func(t *testing.T) {
		result := ReflectUnion([]string{}, []string{"a", "b"})
		assert.Equal(t, []string{"a", "b"}, result)
	})

	t.Run("second empty", func(t *testing.T) {
		result := ReflectUnion([]string{"a", "b"}, []string{})
		assert.Equal(t, []string{"a", "b"}, result)
	})

	t.Run("non-overlapping", func(t *testing.T) {
		result := ReflectUnion([]string{"a", "b"}, []string{"c", "d"})
		assert.ElementsMatch(t, []string{"a", "b", "c", "d"}, result)
	})

	t.Run("overlapping", func(t *testing.T) {
		result := ReflectUnion([]string{"a", "b", "c"}, []string{"b", "c", "d"})
		assert.ElementsMatch(t, []string{"a", "b", "c", "d"}, result)
	})

	t.Run("completely overlapping", func(t *testing.T) {
		result := ReflectUnion([]string{"a", "b"}, []string{"a", "b"})
		assert.ElementsMatch(t, []string{"a", "b"}, result)
	})

	t.Run("single values (slicified)", func(t *testing.T) {
		result := ReflectUnion("a", "b")
		assert.ElementsMatch(t, []string{"a", "b"}, result)
	})

	t.Run("int slices", func(t *testing.T) {
		result := ReflectUnion([]int{1, 2}, []int{2, 3})
		assert.ElementsMatch(t, []int{1, 2, 3}, result)
	})
}

func TestReflectIntersect(t *testing.T) {
	t.Run("both empty", func(t *testing.T) {
		result := ReflectIntersect([]string{}, []string{})
		// ReflectIntersect returns nil slice for empty result
		assert.Empty(t, result)
	})

	t.Run("first empty", func(t *testing.T) {
		result := ReflectIntersect([]string{}, []string{"a", "b"})
		assert.Empty(t, result)
	})

	t.Run("second empty", func(t *testing.T) {
		result := ReflectIntersect([]string{"a", "b"}, []string{})
		assert.Empty(t, result)
	})

	t.Run("no overlap", func(t *testing.T) {
		result := ReflectIntersect([]string{"a", "b"}, []string{"c", "d"})
		assert.Empty(t, result)
	})

	t.Run("partial overlap", func(t *testing.T) {
		result := ReflectIntersect([]string{"a", "b", "c"}, []string{"b", "c", "d"})
		assert.ElementsMatch(t, []string{"b", "c"}, result)
	})

	t.Run("complete overlap", func(t *testing.T) {
		result := ReflectIntersect([]string{"a", "b"}, []string{"a", "b"})
		assert.ElementsMatch(t, []string{"a", "b"}, result)
	})

	t.Run("single values (slicified)", func(t *testing.T) {
		result := ReflectIntersect("a", "a")
		assert.ElementsMatch(t, []string{"a"}, result)
	})

	t.Run("int slices", func(t *testing.T) {
		result := ReflectIntersect([]int{1, 2, 3}, []int{2, 3, 4})
		assert.ElementsMatch(t, []int{2, 3}, result)
	})
}

func TestReflectIsSubsetOf(t *testing.T) {
	t.Run("empty is subset of anything", func(t *testing.T) {
		assert.True(t, ReflectIsSubsetOf([]string{}, []string{"a", "b"}))
	})

	t.Run("empty is subset of empty", func(t *testing.T) {
		assert.True(t, ReflectIsSubsetOf([]string{}, []string{}))
	})

	t.Run("non-empty is not subset of empty", func(t *testing.T) {
		assert.False(t, ReflectIsSubsetOf([]string{"a"}, []string{}))
	})

	t.Run("subset is subset", func(t *testing.T) {
		assert.True(t, ReflectIsSubsetOf([]string{"a", "b"}, []string{"a", "b", "c"}))
	})

	t.Run("equal is subset", func(t *testing.T) {
		assert.True(t, ReflectIsSubsetOf([]string{"a", "b"}, []string{"a", "b"}))
	})

	t.Run("superset is not subset", func(t *testing.T) {
		assert.False(t, ReflectIsSubsetOf([]string{"a", "b", "c"}, []string{"a", "b"}))
	})

	t.Run("partial overlap is not subset", func(t *testing.T) {
		assert.False(t, ReflectIsSubsetOf([]string{"a", "b", "d"}, []string{"a", "b", "c"}))
	})

	t.Run("single values (slicified)", func(t *testing.T) {
		assert.True(t, ReflectIsSubsetOf("a", []string{"a", "b"}))
	})
}

func TestReflectIsSupersetOf(t *testing.T) {
	t.Run("anything is superset of empty", func(t *testing.T) {
		assert.True(t, ReflectIsSupersetOf([]string{"a", "b"}, []string{}))
	})

	t.Run("empty is superset of empty", func(t *testing.T) {
		assert.True(t, ReflectIsSupersetOf([]string{}, []string{}))
	})

	t.Run("empty is not superset of non-empty", func(t *testing.T) {
		assert.False(t, ReflectIsSupersetOf([]string{}, []string{"a"}))
	})

	t.Run("superset is superset", func(t *testing.T) {
		assert.True(t, ReflectIsSupersetOf([]string{"a", "b", "c"}, []string{"a", "b"}))
	})

	t.Run("equal is superset", func(t *testing.T) {
		assert.True(t, ReflectIsSupersetOf([]string{"a", "b"}, []string{"a", "b"}))
	})

	t.Run("subset is not superset", func(t *testing.T) {
		assert.False(t, ReflectIsSupersetOf([]string{"a", "b"}, []string{"a", "b", "c"}))
	})
}

func TestSliceEqual(t *testing.T) {
	t.Run("nil equals nil", func(t *testing.T) {
		assert.True(t, SliceEqual(nil, nil))
	})

	t.Run("nil does not equal non-nil", func(t *testing.T) {
		assert.False(t, SliceEqual(nil, []string{"a"}))
		assert.False(t, SliceEqual([]string{"a"}, nil))
	})

	t.Run("empty slices are equal", func(t *testing.T) {
		assert.True(t, SliceEqual([]string{}, []string{}))
	})

	t.Run("same elements same order", func(t *testing.T) {
		assert.True(t, SliceEqual([]string{"a", "b", "c"}, []string{"a", "b", "c"}))
	})

	t.Run("same elements different order", func(t *testing.T) {
		assert.True(t, SliceEqual([]string{"a", "b", "c"}, []string{"c", "b", "a"}))
	})

	t.Run("different lengths", func(t *testing.T) {
		assert.False(t, SliceEqual([]string{"a", "b"}, []string{"a", "b", "c"}))
	})

	t.Run("different elements", func(t *testing.T) {
		assert.False(t, SliceEqual([]string{"a", "b"}, []string{"a", "c"}))
	})

	t.Run("single values (slicified)", func(t *testing.T) {
		assert.True(t, SliceEqual("a", "a"))
		assert.False(t, SliceEqual("a", "b"))
	})

	t.Run("int slices", func(t *testing.T) {
		assert.True(t, SliceEqual([]int{1, 2, 3}, []int{3, 2, 1}))
		assert.False(t, SliceEqual([]int{1, 2, 3}, []int{1, 2, 4}))
	})
}
