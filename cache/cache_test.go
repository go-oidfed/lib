package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testStruct is a sample struct for testing cache serialization
type testStruct struct {
	Name  string `msgpack:"name"`
	Value int    `msgpack:"value"`
}

func TestCacheWrapper_SetAndGet(t *testing.T) {
	c := newCacheWrapper(time.Hour)

	t.Run("string value", func(t *testing.T) {
		err := c.Set("test-string", "hello", time.Hour)
		require.NoError(t, err)

		var result string
		found, err := c.Get("test-string", &result)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, "hello", result)
	})

	t.Run("int value", func(t *testing.T) {
		err := c.Set("test-int", 42, time.Hour)
		require.NoError(t, err)

		var result int
		found, err := c.Get("test-int", &result)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, 42, result)
	})

	t.Run("struct value", func(t *testing.T) {
		original := testStruct{Name: "test", Value: 123}
		err := c.Set("test-struct", original, time.Hour)
		require.NoError(t, err)

		var result testStruct
		found, err := c.Get("test-struct", &result)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, original, result)
	})

	t.Run("slice value", func(t *testing.T) {
		original := []string{"a", "b", "c"}
		err := c.Set("test-slice", original, time.Hour)
		require.NoError(t, err)

		var result []string
		found, err := c.Get("test-slice", &result)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, original, result)
	})

	t.Run("map value", func(t *testing.T) {
		original := map[string]int{"a": 1, "b": 2}
		err := c.Set("test-map", original, time.Hour)
		require.NoError(t, err)

		var result map[string]int
		found, err := c.Get("test-map", &result)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, original, result)
	})
}

func TestCacheWrapper_GetMiss(t *testing.T) {
	c := newCacheWrapper(time.Hour)

	var result string
	found, err := c.Get("nonexistent-key", &result)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, "", result)
}

func TestCacheWrapper_Delete(t *testing.T) {
	c := newCacheWrapper(time.Hour)

	// Set a value
	err := c.Set("to-delete", "value", time.Hour)
	require.NoError(t, err)

	// Verify it exists
	var result string
	found, err := c.Get("to-delete", &result)
	require.NoError(t, err)
	assert.True(t, found)

	// Delete it
	err = c.Delete("to-delete")
	require.NoError(t, err)

	// Verify it's gone
	found, err = c.Get("to-delete", &result)
	require.NoError(t, err)
	assert.False(t, found)
}

func TestCacheWrapper_Clear(t *testing.T) {
	c := newCacheWrapper(time.Hour)

	// Set multiple values with same prefix
	require.NoError(t, c.Set("prefix:key1", "value1", time.Hour))
	require.NoError(t, c.Set("prefix:key2", "value2", time.Hour))
	require.NoError(t, c.Set("other:key3", "value3", time.Hour))

	// Clear by prefix
	err := c.Clear("prefix:")
	require.NoError(t, err)

	// Verify prefix keys are gone
	var result string
	found, _ := c.Get("prefix:key1", &result)
	assert.False(t, found)
	found, _ = c.Get("prefix:key2", &result)
	assert.False(t, found)

	// Verify other key still exists
	found, _ = c.Get("other:key3", &result)
	assert.True(t, found)
}

func TestNoopCache(t *testing.T) {
	c := noopCache{}

	t.Run("Get always misses", func(t *testing.T) {
		var result string
		found, err := c.Get("any-key", &result)
		assert.NoError(t, err)
		assert.False(t, found)
	})

	t.Run("Set does nothing", func(t *testing.T) {
		err := c.Set("key", "value", time.Hour)
		assert.NoError(t, err)

		// Verify nothing was stored
		var result string
		found, _ := c.Get("key", &result)
		assert.False(t, found)
	})

	t.Run("Delete does nothing", func(t *testing.T) {
		err := c.Delete("key")
		assert.NoError(t, err)
	})

	t.Run("Clear does nothing", func(t *testing.T) {
		err := c.Clear("prefix")
		assert.NoError(t, err)
	})
}

func TestUseNoopCache(t *testing.T) {
	// Save original cache
	originalCache := cacheCache
	defer func() { cacheCache = originalCache }()

	UseNoopCache()

	// Verify noop behavior through package-level functions
	err := Set("test-key", "test-value", time.Hour)
	require.NoError(t, err)

	var result string
	found, err := Get("test-key", &result)
	require.NoError(t, err)
	assert.False(t, found) // Should always miss with noop cache
}

func TestKey(t *testing.T) {
	tests := []struct {
		name     string
		parts    []string
		expected string
	}{
		{
			name:     "single part",
			parts:    []string{"entity_statement"},
			expected: "entity_statement",
		},
		{
			name:     "two parts",
			parts:    []string{"entity_statement", "abc123"},
			expected: "entity_statement:abc123",
		},
		{
			name:     "multiple parts",
			parts:    []string{"a", "b", "c", "d"},
			expected: "a:b:c:d",
		},
		{
			name:     "empty",
			parts:    []string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Key(tt.parts...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEntityStmtCacheKey(t *testing.T) {
	key := EntityStmtCacheKey("https://example.com/entity", "https://issuer.com")

	// Should start with the entity statement prefix
	assert.Contains(t, key, KeyEntityStatement)

	// Should contain base64-encoded parts separated by colon
	assert.Contains(t, key, ":")

	// Same inputs should produce same key
	key2 := EntityStmtCacheKey("https://example.com/entity", "https://issuer.com")
	assert.Equal(t, key, key2)

	// Different inputs should produce different keys
	key3 := EntityStmtCacheKey("https://other.com/entity", "https://issuer.com")
	assert.NotEqual(t, key, key3)
}

func TestPackageLevelFunctions(t *testing.T) {
	// Use a fresh cache for this test
	originalCache := cacheCache
	defer func() { cacheCache = originalCache }()

	SetCache(newCacheWrapper(time.Hour))

	t.Run("Set and Get", func(t *testing.T) {
		err := Set("pkg-test-key", "pkg-test-value", time.Hour)
		require.NoError(t, err)

		var result string
		found, err := Get("pkg-test-key", &result)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, "pkg-test-value", result)
	})

	t.Run("Delete", func(t *testing.T) {
		err := Set("pkg-delete-key", "value", time.Hour)
		require.NoError(t, err)

		err = Delete("pkg-delete-key")
		require.NoError(t, err)

		var result string
		found, _ := Get("pkg-delete-key", &result)
		assert.False(t, found)
	})

	t.Run("Clear", func(t *testing.T) {
		require.NoError(t, Set("pkg-clear:a", "1", time.Hour))
		require.NoError(t, Set("pkg-clear:b", "2", time.Hour))

		err := Clear("pkg-clear:")
		require.NoError(t, err)

		var result string
		found, _ := Get("pkg-clear:a", &result)
		assert.False(t, found)
		found, _ = Get("pkg-clear:b", &result)
		assert.False(t, found)
	})
}

func TestSetMaxLifetime(t *testing.T) {
	// Save original state
	originalCache := cacheCache
	originalMaxLifetime := maxLifetime
	defer func() {
		cacheCache = originalCache
		maxLifetime = originalMaxLifetime
	}()

	SetCache(newCacheWrapper(time.Hour))

	t.Run("clamps TTL when max is set", func(t *testing.T) {
		SetMaxLifetime(time.Minute)

		// Even though we request 1 hour, it should be clamped
		err := Set("max-lifetime-test", "value", time.Hour)
		require.NoError(t, err)

		// Value should still be retrievable
		var result string
		found, err := Get("max-lifetime-test", &result)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, "value", result)
	})

	t.Run("no clamping when max is zero", func(t *testing.T) {
		SetMaxLifetime(0)

		err := Set("no-max-test", "value", time.Hour)
		require.NoError(t, err)

		var result string
		found, err := Get("no-max-test", &result)
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("no clamping when TTL is less than max", func(t *testing.T) {
		SetMaxLifetime(time.Hour)

		err := Set("under-max-test", "value", time.Minute)
		require.NoError(t, err)

		var result string
		found, err := Get("under-max-test", &result)
		require.NoError(t, err)
		assert.True(t, found)
	})
}

func TestSetCache(t *testing.T) {
	// Save original cache
	originalCache := cacheCache
	defer func() { cacheCache = originalCache }()

	// Create a custom mock cache
	mockCache := &mockCacheImpl{data: make(map[string]any)}
	SetCache(mockCache)

	// Verify the new cache is used
	err := Set("mock-test", "mock-value", time.Hour)
	require.NoError(t, err)

	// The mock should have stored the value
	assert.Contains(t, mockCache.data, "mock-test")
}

// mockCacheImpl is a simple mock for testing SetCache
type mockCacheImpl struct {
	data map[string]any
}

func (m *mockCacheImpl) Get(key string, target any) (bool, error) {
	_, ok := m.data[key]
	return ok, nil
}

func (m *mockCacheImpl) Set(key string, value any, _ time.Duration) error {
	m.data[key] = value
	return nil
}

func (m *mockCacheImpl) Delete(key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockCacheImpl) Clear(prefix string) error {
	for k := range m.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(m.data, k)
		}
	}
	return nil
}

func TestCacheConstants(t *testing.T) {
	// Verify cache key constants are defined
	assert.NotEmpty(t, KeyEntityStatement)
	assert.NotEmpty(t, KeyOPMetadata)
	assert.NotEmpty(t, KeyEntityConfiguration)
	assert.NotEmpty(t, KeyTrustTree)
	assert.NotEmpty(t, KeyTrustTreeChains)
	assert.NotEmpty(t, KeyTrustChainResolvedMetadata)
	assert.NotEmpty(t, KeySubordinateListing)
	assert.NotEmpty(t, KeyExplicitRegistration)
}
