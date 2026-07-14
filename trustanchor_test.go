package oidfed

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/go-oidfed/lib/jwx"
)

func TestTrustAnchor_UnmarshalYAML_LegacyJWKS(t *testing.T) {
	// Use a properly formatted JWKS with valid base64url-encoded values
	yamlContent := `
entity_id: https://ta.example.com
jwks:
  keys:
    - kty: RSA
      kid: test-key
      n: 0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw
      e: AQAB
`
	var ta TrustAnchor
	err := yaml.Unmarshal([]byte(yamlContent), &ta)
	require.NoError(t, err)

	assert.Equal(t, "https://ta.example.com", ta.EntityID)
	assert.False(t, ta.EnableJWKSUpdate)
	assert.Zero(t, ta.KeyPollInterval.Duration())

	jwks := ta.JWKS()
	assert.NotNil(t, jwks.Set)
}

func TestTrustAnchor_UnmarshalYAML_JWKSFile(t *testing.T) {
	// Create a temporary JWKS file
	tmpDir := t.TempDir()
	jwksFilePath := filepath.Join(tmpDir, "test-jwks.json")

	// Use a properly formatted JWKS with valid base64url-encoded RSA key
	jwksData := `{
		"keys": [
			{
				"kty": "RSA",
				"kid": "file-key",
				"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e": "AQAB"
			}
		]
	}`

	err := os.WriteFile(jwksFilePath, []byte(jwksData), 0o644)
	require.NoError(t, err)

	yamlContent := `
entity_id: https://ta-file.example.com
jwks_file: ` + jwksFilePath + `
enable_jwks_update: true
key_poll_interval: 2h
`

	var ta TrustAnchor
	err = yaml.Unmarshal([]byte(yamlContent), &ta)
	require.NoError(t, err)

	assert.Equal(t, "https://ta-file.example.com", ta.EntityID)
	assert.Equal(t, jwksFilePath, ta.JWKSFile)
	assert.True(t, ta.EnableJWKSUpdate)
	assert.Equal(t, 2*time.Hour, ta.KeyPollInterval.Duration())

	jwks := ta.JWKS()
	assert.NotNil(t, jwks.Set)
	assert.GreaterOrEqual(t, jwks.Len(), 1)
}

func TestTrustAnchor_UnmarshalYAML_FileNotFound(t *testing.T) {
	yamlContent := `
entity_id: https://ta.example.com
jwks_file: /nonexistent/path/to/jwks.json
`

	var ta TrustAnchor
	err := yaml.Unmarshal([]byte(yamlContent), &ta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load JWks from file")
}

func TestTrustAnchor_JWKS_ThreadSafe(t *testing.T) {
	var ta TrustAnchor

	// Set initial JWKS
	initialJWKS := jwx.NewJWKS()
	ta.SetJWKS(initialJWKS)

	// Concurrent reads should not panic
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = ta.JWKS()
			}
			done <- true
		}()
	}

	// Concurrent writes
	go func() {
		for k := 0; k < 100; k++ {
			newJWKS := jwx.NewJWKS()
			ta.SetJWKS(newJWKS)
		}
	}()

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should still be able to read without panic
	finalJWKS := ta.JWKS()
	assert.NotNil(t, finalJWKS.Set)
}

func TestHasJWKSChanged_NoChange(t *testing.T) {
	jwks1 := jwx.NewJWKS()
	jwks2 := jwx.NewJWKS()

	changed, added, removed := hasJWKSChanged(extractKIDs(jwks1), extractKIDs(jwks2))
	assert.False(t, changed)
	assert.Empty(t, added)
	assert.Empty(t, removed)
}

func TestHasJWKSChanged_KeyAdded(t *testing.T) {
	jwks1 := jwx.NewJWKS()
	jwks2 := jwx.NewJWKS()

	// Use valid base64url-encoded RSA key modulus
	jwksData := `{
		"keys": [
			{
				"kty": "RSA",
				"kid": "new-key",
				"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e": "AQAB"
			}
		]
	}`
	err := jwks2.UnmarshalJSON([]byte(jwksData))
	require.NoError(t, err)

	changed, added, removed := hasJWKSChanged(extractKIDs(jwks1), extractKIDs(jwks2))
	assert.True(t, changed)
	assert.Contains(t, added, "new-key")
	assert.Empty(t, removed)
}

func TestHasJWKSChanged_KeyRemoved(t *testing.T) {
	jwks1 := jwx.NewJWKS()
	jwks2 := jwx.NewJWKS()

	// Use valid base64url-encoded RSA key modulus
	jwksData := `{
		"keys": [
			{
				"kty": "RSA",
				"kid": "old-key",
				"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e": "AQAB"
			}
		]
	}`
	err := jwks1.UnmarshalJSON([]byte(jwksData))
	require.NoError(t, err)

	changed, added, removed := hasJWKSChanged(extractKIDs(jwks1), extractKIDs(jwks2))
	assert.True(t, changed)
	assert.Empty(t, added)
	assert.Contains(t, removed, "old-key")
}

func TestFileJWKStorage_UpdateAndGet(t *testing.T) {
	tmpDir := t.TempDir()

	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	entityID := "https://example.com"
	testJWKS := jwx.NewJWKS()

	// Update
	err = storage.UpdateJWKS(entityID, testJWKS)
	require.NoError(t, err)

	// Get
	retrieved, err := storage.GetJWKS(entityID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
}

func TestFileJWKStorage_CreatesDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "nested", "path")

	storage, err := NewFileJWKStorage(nestedDir)
	require.NoError(t, err)

	entityID := "https://example.com"
	testJWKS := jwx.NewJWKS()

	err = storage.UpdateJWKS(entityID, testJWKS)
	require.NoError(t, err)

	// Verify directory was created
	_, err = os.Stat(nestedDir)
	require.NoError(t, err)
}

func TestFileJWKStorage_GetNonExistent(t *testing.T) {
	tmpDir := t.TempDir()

	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	retrieved, err := storage.GetJWKS("https://nonexistent.com")
	require.NoError(t, err)
	assert.Nil(t, retrieved)
}

func TestEncodedDecodedEntityID(t *testing.T) {
	entityID := "https://example.com/entity/path"
	encoded := encodedEntityID(entityID)
	decoded, err := DecodedEntityID(encoded)
	require.NoError(t, err)
	assert.Equal(t, entityID, decoded)
}

func TestTAJWKSRefresher_StartupMerge(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	entityID := "https://ta-merge.example.com"

	// Simulate previously refreshed keys persisted in storage
	storedJWKS := createTestJWKS(t, "stored-key")
	err = storage.UpdateJWKS(entityID, *storedJWKS)
	require.NoError(t, err)

	// Create a TA with config JWKS containing a different key
	configJWKS := createTestJWKS(t, "config-key")
	ta := &TrustAnchor{
		EntityID:         entityID,
		EnableJWKSUpdate: true,
	}
	ta.SetJWKS(*configJWKS)

	tas := TrustAnchors{ta}

	// Build the refresher (registers jwks_file paths if set — none here)
	refresher, err := NewTAJWKSRefresher(&tas, storage)
	require.NoError(t, err)

	// Simulate the merge logic from Start() without calling Start()
	// (Start() would also do an HTTP poll which we can't do in a unit test)
	for _, ta := range tas {
		if !ta.EnableJWKSUpdate {
			continue
		}
		gotStored, err := refresher.storage.GetJWKS(ta.EntityID)
		require.NoError(t, err)
		require.NotNil(t, gotStored)

		configJWKS := ta.JWKS()
		merged := jwx.MergeJWKS(configJWKS, *gotStored)
		ta.SetJWKS(merged)
	}

	// Verify the TA now has both keys
	finalJWKS := ta.JWKS()
	assert.Equal(t, 2, finalJWKS.Len())

	kids := map[string]bool{}
	for _, k := range finalJWKS.All() {
		if kid, ok := k.KeyID(); ok {
			kids[kid] = true
		}
	}
	assert.True(t, kids["config-key"], "config key should be present after merge")
	assert.True(t, kids["stored-key"], "stored key should be present after merge")
}
