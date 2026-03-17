package utils

import (
	"reflect"
	"testing"
)

func TestNilAllExceptByTag(t *testing.T) {
	type TaggedStruct struct {
		HasTag    *struct{} `json:"has_tag"`
		OtherTag  *struct{} `json:"other_tag"`
		NoTag     *struct{}
		OmitEmpty *struct{} `json:"omit_empty,omitempty"`
		YAMLTag   *struct{} `yaml:"yaml_tag"`
		Extra     map[string]any
	}

	tests := []struct {
		name     string
		input    TaggedStruct
		jsonTags []string
		expected TaggedStruct
	}{
		{
			name: "no extra",
			input: TaggedStruct{
				HasTag:    &struct{}{},
				OtherTag:  &struct{}{},
				NoTag:     &struct{}{},
				OmitEmpty: &struct{}{},
				YAMLTag:   &struct{}{},
				Extra:     nil,
			},
			jsonTags: []string{
				"has_tag", "NoTag", "omit_empty", "yaml_tag",
			},
			expected: TaggedStruct{
				HasTag:    &struct{}{},
				OtherTag:  nil,
				NoTag:     &struct{}{},
				OmitEmpty: &struct{}{},
				YAMLTag:   nil,
				Extra:     nil,
			},
		},
		{
			name: "with extra",
			input: TaggedStruct{
				HasTag: &struct{}{},
				Extra: map[string]any{
					"key1": &struct{}{},
					"key2": &struct{}{},
				},
			},
			jsonTags: []string{"key1"},
			expected: TaggedStruct{
				Extra: map[string]any{"key1": &struct{}{}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			NilAllExceptByTag(&test.input, test.jsonTags)
			if !reflect.DeepEqual(test.input, test.expected) {
				t.Errorf("NilAllExceptByTag: sanitized struct has unexpected value %+v", test.input)
			}
		})
	}
}

func TestNilAllExceptByTagExtraWrongType(t *testing.T) {
	type ExtraWrongType struct {
		Extra map[string]int
	}

	input := ExtraWrongType{Extra: map[string]int{"key": 1}}
	NilAllExceptByTag(&input, []string{"key"})

	if !reflect.DeepEqual(input, ExtraWrongType{Extra: nil}) {
		t.Errorf("NilAllExceptByTag: sanitized struct has unexpected Extra value %+v", input)
	}
}

func TestHashStruct(t *testing.T) {
	type testStruct struct {
		Name  string `msgpack:"name"`
		Value int    `msgpack:"value"`
	}

	t.Run("consistent hashing", func(t *testing.T) {
		input := testStruct{Name: "test", Value: 42}

		hash1, err1 := HashStruct(input)
		hash2, err2 := HashStruct(input)

		if err1 != nil {
			t.Fatalf("HashStruct returned error: %v", err1)
		}
		if err2 != nil {
			t.Fatalf("HashStruct returned error: %v", err2)
		}
		if hash1 != hash2 {
			t.Errorf("HashStruct: same input produced different hashes: %s vs %s", hash1, hash2)
		}
	})

	t.Run("different inputs produce different hashes", func(t *testing.T) {
		input1 := testStruct{Name: "test", Value: 42}
		input2 := testStruct{Name: "test", Value: 43}

		hash1, err1 := HashStruct(input1)
		hash2, err2 := HashStruct(input2)

		if err1 != nil {
			t.Fatalf("HashStruct returned error: %v", err1)
		}
		if err2 != nil {
			t.Fatalf("HashStruct returned error: %v", err2)
		}
		if hash1 == hash2 {
			t.Errorf("HashStruct: different inputs produced same hash: %s", hash1)
		}
	})

	t.Run("hash is non-empty", func(t *testing.T) {
		input := testStruct{Name: "test", Value: 42}
		hash, err := HashStruct(input)

		if err != nil {
			t.Fatalf("HashStruct returned error: %v", err)
		}
		if hash == "" {
			t.Error("HashStruct: returned empty hash")
		}
	})

	t.Run("hash is base64 URL encoded", func(t *testing.T) {
		input := testStruct{Name: "test", Value: 42}
		hash, err := HashStruct(input)

		if err != nil {
			t.Fatalf("HashStruct returned error: %v", err)
		}

		// Base64 URL encoding should not contain + or /
		for _, c := range hash {
			if c == '+' || c == '/' {
				t.Errorf("HashStruct: hash contains non-URL-safe characters: %s", hash)
				break
			}
		}
	})

	t.Run("nil struct", func(t *testing.T) {
		hash, err := HashStruct(nil)
		// Should not error, just hash the nil value
		if err != nil {
			t.Fatalf("HashStruct returned error for nil: %v", err)
		}
		if hash == "" {
			t.Error("HashStruct: returned empty hash for nil")
		}
	})

	t.Run("empty struct", func(t *testing.T) {
		input := testStruct{}
		hash, err := HashStruct(input)

		if err != nil {
			t.Fatalf("HashStruct returned error: %v", err)
		}
		if hash == "" {
			t.Error("HashStruct: returned empty hash for empty struct")
		}
	})

	t.Run("map type", func(t *testing.T) {
		input := map[string]any{"key": "value", "number": 42}
		hash, err := HashStruct(input)

		if err != nil {
			t.Fatalf("HashStruct returned error: %v", err)
		}
		if hash == "" {
			t.Error("HashStruct: returned empty hash for map")
		}
	})

	t.Run("slice type", func(t *testing.T) {
		input := []string{"a", "b", "c"}
		hash, err := HashStruct(input)

		if err != nil {
			t.Fatalf("HashStruct returned error: %v", err)
		}
		if hash == "" {
			t.Error("HashStruct: returned empty hash for slice")
		}
	})
}
