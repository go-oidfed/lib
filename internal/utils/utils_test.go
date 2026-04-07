package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEqual(t *testing.T) {
	t.Run("empty values list", func(t *testing.T) {
		// With no values to compare against, result is true (vacuous truth)
		assert.True(t, Equal(1))
	})

	t.Run("single value equal", func(t *testing.T) {
		assert.True(t, Equal(1, 1))
	})

	t.Run("single value not equal", func(t *testing.T) {
		assert.False(t, Equal(1, 2))
	})

	t.Run("all values equal", func(t *testing.T) {
		assert.True(t, Equal(5, 5, 5, 5))
	})

	t.Run("one value different", func(t *testing.T) {
		assert.False(t, Equal(5, 5, 5, 6))
	})

	t.Run("first value different", func(t *testing.T) {
		assert.False(t, Equal(5, 6, 5, 5))
	})

	t.Run("strings equal", func(t *testing.T) {
		assert.True(t, Equal("hello", "hello", "hello"))
	})

	t.Run("strings not equal", func(t *testing.T) {
		assert.False(t, Equal("hello", "hello", "world"))
	})

	t.Run("booleans equal", func(t *testing.T) {
		assert.True(t, Equal(true, true, true))
	})

	t.Run("booleans not equal", func(t *testing.T) {
		assert.False(t, Equal(true, true, false))
	})
}

func TestIsMap(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected bool
	}{
		{
			name:     "string to int map",
			input:    map[string]int{"a": 1},
			expected: true,
		},
		{
			name:     "string to any map",
			input:    map[string]any{"key": "value"},
			expected: true,
		},
		{
			name:     "int to string map",
			input:    map[int]string{1: "one"},
			expected: true,
		},
		{
			name:     "empty map",
			input:    map[string]int{},
			expected: true,
		},
		{
			name:     "slice",
			input:    []string{"a", "b"},
			expected: false,
		},
		{
			name:     "string",
			input:    "not a map",
			expected: false,
		},
		{
			name:     "int",
			input:    42,
			expected: false,
		},
		{
			name:     "struct",
			input:    struct{ Name string }{Name: "test"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMap(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
