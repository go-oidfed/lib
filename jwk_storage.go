package oidfed

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/jwx"
)

// JWKStorage is an interface for persisting JWKS updates
type JWKStorage interface {
	// UpdateJWKS stores the complete JWKS for an entity
	// Replaces any existing JWKS for this entityID
	UpdateJWKS(entityID string, jwks jwx.JWKS) error
	// GetJWKS retrieves stored JWKS
	// Returns nil, nil if no JWKS is stored for the entityID
	GetJWKS(entityID string) (*jwx.JWKS, error)
	// RegisterEntityJWKSFile registers an explicit JWKS file path for an entity
	// The storage may use this path for read/write operations instead of the default location
	RegisterEntityJWKSFile(entityID, jwksFile string) error
}

// FileJWKStorage implements JWKStorage using the filesystem
type FileJWKStorage struct {
	Dir         string
	mu          sync.RWMutex
	entityFiles map[string]string // entityID → absolute jwks_file path
}

// NewFileJWKStorage creates a new FileJWKStorage
// Creates the directory if it doesn't exist
func NewFileJWKStorage(dir string) (*FileJWKStorage, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	// Convert to absolute path
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	return &FileJWKStorage{
		Dir:         absDir,
		entityFiles: make(map[string]string),
	}, nil
}

// UpdateJWKS implements JWKStorage.UpdateJWKS
// Stores JWKS as JSON file at the registered jwks_file path if set, otherwise at <Dir>/<base64url(entityID)>.json
func (f *FileJWKStorage) UpdateJWKS(entityID string, jwks jwx.JWKS) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var filePath string
	if registeredPath, ok := f.entityFiles[entityID]; ok {
		filePath = registeredPath
		// Create parent directories if needed
		if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
			return err
		}
	} else {
		filePath = f.filepathForEntityID(entityID)
	}

	data, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0o644)
}

// GetJWKS implements JWKStorage.GetJWKS
func (f *FileJWKStorage) GetJWKS(entityID string) (*jwx.JWKS, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var filePath string
	if registeredPath, ok := f.entityFiles[entityID]; ok {
		filePath = registeredPath
	} else {
		filePath = f.filepathForEntityID(entityID)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var jwks jwx.JWKS
	if err = jwks.UnmarshalJSON(data); err != nil {
		return nil, err
	}

	return &jwks, nil
}

// filepathForEntityID returns the file path for storing an entity's JWKS
func (f *FileJWKStorage) filepathForEntityID(entityID string) string {
	return filepath.Join(f.Dir, encodedEntityID(entityID)+".json")
}

// RegisterEntityJWKSFile registers an explicit JWKS file path for an entity
// Creates a symlink from the default location to the specified file
// Validates that jwksFile is an absolute path
func (f *FileJWKStorage) RegisterEntityJWKSFile(entityID, jwksFile string) error {
	if !filepath.IsAbs(jwksFile) {
		return errors.Errorf("jwks_file must be an absolute path, got %q", jwksFile)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Store the mapping
	f.entityFiles[entityID] = jwksFile

	// Create symlink: <Dir>/<encoded-entity-id>.json -> <jwksFile>
	symlinkPath := f.filepathForEntityID(entityID)

	// Remove existing symlink if present (best effort, ignore errors)
	if info, err := os.Lstat(symlinkPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		os.Remove(symlinkPath)
	}

	// Create new symlink
	if err := os.Symlink(jwksFile, symlinkPath); err != nil {
		internal.Logger().Warn().Err(err).
			Str("entity_id", entityID).
			Str("target", jwksFile).
			Msg("Failed to create JWKS symlink")
	}

	return nil
}
