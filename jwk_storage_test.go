package oidfed

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-oidfed/lib/jwx"
)

func TestRegisterEntityJWKSFile_ValidPath(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	entityID := "https://example.com"
	jwksFile := filepath.Join(tmpDir, "custom", "jwks.json")

	err = storage.RegisterEntityJWKSFile(entityID, jwksFile)
	assert.NoError(t, err)

	// Verify symlink was created
	symlinkPath := storage.filepathForEntityID(entityID)
	info, err := os.Lstat(symlinkPath)
	require.NoError(t, err)
	assert.True(t, info.Mode()&os.ModeSymlink != 0)

	// Verify symlink points to correct target
	target, err := os.Readlink(symlinkPath)
	assert.NoError(t, err)
	assert.Equal(t, jwksFile, target)
}

func TestRegisterEntityJWKSFile_RelativePath_Errors(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	entityID := "https://example.com"
	relativePath := "./custom/jwks.json"

	err = storage.RegisterEntityJWKSFile(entityID, relativePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be an absolute path")
}

func TestRegisterEntityJWKSFile_SymlinkCreated(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	entityID := "https://example.com"
	jwksFile := filepath.Join(tmpDir, "custom", "jwks.json")

	err = storage.RegisterEntityJWKSFile(entityID, jwksFile)
	require.NoError(t, err)

	symlinkPath := storage.filepathForEntityID(entityID)

	// Verify symlink exists
	info, err := os.Lstat(symlinkPath)
	require.NoError(t, err)
	assert.True(t, info.Mode()&os.ModeSymlink != 0)

	// Verify target
	target, err := os.Readlink(symlinkPath)
	assert.NoError(t, err)
	assert.Equal(t, jwksFile, target)
}

func TestRegisterEntityJWKSFile_SymlinkOverwritten(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	entityID := "https://example.com"
	jwksFile1 := filepath.Join(tmpDir, "jwks1.json")
	jwksFile2 := filepath.Join(tmpDir, "jwks2.json")

	// Register first file
	err = storage.RegisterEntityJWKSFile(entityID, jwksFile1)
	require.NoError(t, err)

	// Register second file (should overwrite symlink)
	err = storage.RegisterEntityJWKSFile(entityID, jwksFile2)
	assert.NoError(t, err)

	// Verify symlink now points to second file
	symlinkPath := storage.filepathForEntityID(entityID)
	target, err := os.Readlink(symlinkPath)
	assert.NoError(t, err)
	assert.Equal(t, jwksFile2, target)
}

func TestRegisterEntityJWKSFile_SymlinkCreationFailure_Warns(t *testing.T) {
	// This test is tricky because we can't easily force symlink creation to fail
	// We'll skip this for now as it requires mocking or special filesystem setup
	t.Skip("Requires filesystem mocking to test symlink failure")
}

func TestUpdateJWKS_WithExplicitFile_WritesToRegisteredPath(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	entityID := "https://example.com"
	jwksFile := filepath.Join(tmpDir, "custom", "jwks.json")

	// Register explicit path
	err = storage.RegisterEntityJWKSFile(entityID, jwksFile)
	require.NoError(t, err)

	// Create JWKS
	jwks := createTestJWKS(t, "test-kid")

	// Update JWKS
	err = storage.UpdateJWKS(entityID, *jwks)
	require.NoError(t, err)

	// Verify file was written to registered path
	_, err = os.Stat(jwksFile)
	assert.NoError(t, err, "JWKS should be written to registered path")

	// Default path should be a symlink (not a regular file)
	defaultPath := storage.filepathForEntityID(entityID)
	info, err := os.Lstat(defaultPath)
	require.NoError(t, err)
	assert.True(t, info.Mode()&os.ModeSymlink != 0, "Default path should be a symlink, not a regular file")
}

func TestUpdateJWKS_WithExplicitFile_CreatesParentDirs(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	entityID := "https://example.com"
	jwksFile := filepath.Join(tmpDir, "deep", "nested", "path", "jwks.json")

	// Register explicit path with non-existent parent dirs
	err = storage.RegisterEntityJWKSFile(entityID, jwksFile)
	require.NoError(t, err)

	// Create JWKS
	jwks := createTestJWKS(t, "test-kid")

	// Update JWKS (should create parent directories)
	err = storage.UpdateJWKS(entityID, *jwks)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(jwksFile)
	assert.NoError(t, err)
}

func TestUpdateJWKS_WithoutExplicitFile_WritesToDefault(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	entityID := "https://example.com"

	// Don't register explicit path - use default

	// Create JWKS
	jwks := createTestJWKS(t, "test-kid")

	// Update JWKS
	err = storage.UpdateJWKS(entityID, *jwks)
	require.NoError(t, err)

	// Verify file was written to default path
	defaultPath := storage.filepathForEntityID(entityID)
	_, err = os.Stat(defaultPath)
	assert.NoError(t, err, "JWKS should be written to default path")
}

func TestGetJWKS_WithExplicitFile_ReadsFromRegisteredPath(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	entityID := "https://example.com"
	jwksFile := filepath.Join(tmpDir, "custom", "jwks.json")

	// Register explicit path
	err = storage.RegisterEntityJWKSFile(entityID, jwksFile)
	require.NoError(t, err)

	// Create and write JWKS directly to registered path
	jwks := createTestJWKS(t, "test-kid")
	data, err := jwks.MarshalJSON()
	require.NoError(t, err)
	err = os.MkdirAll(filepath.Dir(jwksFile), 0o755)
	require.NoError(t, err)
	err = os.WriteFile(jwksFile, data, 0o644)
	require.NoError(t, err)

	// Read JWKS via storage
	retrieved, err := storage.GetJWKS(entityID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, 1, retrieved.Len())
}

func TestGetJWKS_WithExplicitFile_NotExists_ReturnsNilNil(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	entityID := "https://example.com"
	jwksFile := filepath.Join(tmpDir, "nonexistent", "jwks.json")

	// Register explicit path (file doesn't exist)
	err = storage.RegisterEntityJWKSFile(entityID, jwksFile)
	require.NoError(t, err)

	// Try to get JWKS
	retrieved, err := storage.GetJWKS(entityID)
	assert.NoError(t, err)
	assert.Nil(t, retrieved)
}

func TestGetJWKS_WithoutExplicitFile_ReadsFromDefault(t *testing.T) {
	tmpDir := t.TempDir()
	storage, err := NewFileJWKStorage(tmpDir)
	require.NoError(t, err)

	entityID := "https://example.com"

	// Create and write JWKS to default location
	jwks := createTestJWKS(t, "test-kid")
	err = storage.UpdateJWKS(entityID, *jwks)
	require.NoError(t, err)

	// Read JWKS via storage
	retrieved, err := storage.GetJWKS(entityID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, 1, retrieved.Len())
}

// Helper function to create a test JWKS
func createTestJWKS(t *testing.T, kid string) *jwx.JWKS {
	t.Helper()

	// Use valid base64url-encoded RSA key modulus
	jwksData := `{
		"keys": [
			{
				"kty": "RSA",
				"kid": "` + kid + `",
				"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e": "AQAB"
			}
		]
	}`

	var jwks jwx.JWKS
	err := jwks.UnmarshalJSON([]byte(jwksData))
	require.NoError(t, err)

	return &jwks
}
