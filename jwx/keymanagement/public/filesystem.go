package public

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"

	log "github.com/go-oidfed/lib/internal"

	"github.com/go-oidfed/lib/unixtime"
)

// FilesystemPublicKeyStorage implements PublicKeyStorage backed by a JSON file on disk.
// It persists a collection of PublicKeyEntry records under a type-specific path.
type FilesystemPublicKeyStorage struct {
	Dir    string
	TypeID string

	mu      sync.RWMutex
	entries map[string]PublicKeyEntry // keyed by KID
}

func (fs *FilesystemPublicKeyStorage) storageFilePath() string {
	return filepath.Join(fs.Dir, fs.TypeID+"_public.json")
}

// Load loads public keys from disk. If no native storage file exists, it attempts
// to import from a legacy LegacyPKCollection persisted via keys.jwks and history files.
func (fs *FilesystemPublicKeyStorage) Load() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.entries == nil {
		fs.entries = make(map[string]PublicKeyEntry)
	}

	data, err := os.ReadFile(fs.storageFilePath())
	if err != nil {
		log.WithError(err).WithField(
			"filepath", fs.storageFilePath(),
		).Warn("FilesystemPublicKeyStorage: could not read storage file")
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	var disk map[string]PublicKeyEntry
	if err = json.Unmarshal(data, &disk); err != nil {
		return errors.WithStack(err)
	}
	fs.entries = disk
	return nil
}

// GetAll returns all keys in the storage, including revoked and expired keys.
func (fs *FilesystemPublicKeyStorage) GetAll() (PublicKeyEntryList, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.snapshot(), nil
}

// GetRevoked returns all revoked keys in the storage.
func (fs *FilesystemPublicKeyStorage) GetRevoked() (PublicKeyEntryList, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	now := time.Now()
	var out PublicKeyEntryList
	for _, e := range fs.entries {
		if !e.RevokedAt.IsZero() && e.RevokedAt.Before(now) {
			out = append(out, e)
		}
	}
	return out, nil
}

// GetExpired returns all expired keys in the storage.
func (fs *FilesystemPublicKeyStorage) GetExpired() (PublicKeyEntryList, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	now := time.Now()
	var out PublicKeyEntryList
	for _, e := range fs.entries {
		if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now) {
			out = append(out, e)
		}
	}
	return out, nil
}

// GetHistorical returns revoked and expired keys.
func (fs *FilesystemPublicKeyStorage) GetHistorical() (PublicKeyEntryList, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	now := time.Now()
	var out PublicKeyEntryList
	for _, e := range fs.entries {
		if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now) {
			out = append(out, e)
		} else if !e.RevokedAt.IsZero() && e.RevokedAt.Before(now) {
			out = append(out, e)
		}
	}
	return out, nil

}

// GetActive returns keys that are currently usable (not revoked and within nbf/exp window).
func (fs *FilesystemPublicKeyStorage) GetActive() (PublicKeyEntryList, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	now := time.Now()
	var out PublicKeyEntryList
	for _, e := range fs.entries {
		if !e.RevokedAt.IsZero() && e.RevokedAt.Before(now) {
			continue
		}
		if !e.NotBefore.IsZero() && now.Before(e.NotBefore.Time) {
			continue
		}
		if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// GetValid returns keys that are valid now or in the future (not revoked or expired).
func (fs *FilesystemPublicKeyStorage) GetValid() (PublicKeyEntryList, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	now := time.Now()
	var out PublicKeyEntryList
	for _, e := range fs.entries {
		if !e.RevokedAt.IsZero() && e.RevokedAt.Before(now) {
			continue
		}
		if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// Add adds a new key to the storage if the KID is unused.
func (fs *FilesystemPublicKeyStorage) Add(key PublicKeyEntry) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if key.KID == "" {
		// Attempt to derive KID from key if missing
		var kid string
		_ = key.Key.Get("kid", &kid)
		key.KID = kid
	}
	if key.KID == "" {
		return errors.New("missing kid for public key entry")
	}
	if _, exists := fs.entries[key.KID]; exists {
		return nil
	}
	fs.entries[key.KID] = key
	return fs.persist()
}

// AddAll adds multiple keys to the storage.
func (fs *FilesystemPublicKeyStorage) AddAll(keys []PublicKeyEntry) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for _, key := range keys {
		if key.KID == "" {
			var kid string
			_ = key.Key.Get("kid", &kid)
			key.KID = kid
		}
		if key.KID == "" {
			continue
		}
		if _, exists := fs.entries[key.KID]; exists {
			continue
		}
		fs.entries[key.KID] = key
	}
	return fs.persist()
}

// Update updates the editable metadata for a given key.
func (fs *FilesystemPublicKeyStorage) Update(kid string, data UpdateablePublicKeyMetadata) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	e, ok := fs.entries[kid]
	if !ok {
		return errors.Errorf("unknown kid '%s'", kid)
	}
	e.UpdateablePublicKeyMetadata = data
	fs.entries[kid] = e
	return fs.persist()
}

// Clear removes all keys from the storage.
func (fs *FilesystemPublicKeyStorage) Clear() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.entries = make(map[string]PublicKeyEntry)
	return fs.persist()
}

// Delete removes a key by kid.
func (fs *FilesystemPublicKeyStorage) Delete(kid string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.entries, kid)
	return fs.persist()
}

// Revoke marks the given key as revoked with the passed reason.
func (fs *FilesystemPublicKeyStorage) Revoke(kid, reason string) error {
	k, err := fs.Get(kid)
	if err != nil {
		return err
	}
	if k == nil {
		return nil
	}
	k.RevokedAt = unixtime.Now()
	k.Reason = reason
	return fs.Update(kid, k.UpdateablePublicKeyMetadata)

}

// Get fetches a key by kid.
func (fs *FilesystemPublicKeyStorage) Get(kid string) (*PublicKeyEntry, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	e, ok := fs.entries[kid]
	if !ok {
		return nil, nil
	}
	// Clone the jwk.Key to avoid external mutation
	if e.Key != nil {
		if k, err := e.Key.Clone(); err == nil {
			e.Key = k
		}
	}
	return &e, nil
}

// snapshot returns a copy of entries as a list.
func (fs *FilesystemPublicKeyStorage) snapshot() PublicKeyEntryList {
	out := make(PublicKeyEntryList, 0, len(fs.entries))
	for _, e := range fs.entries {
		out = append(out, e)
	}
	return out
}

// persist writes the storage to disk.
func (fs *FilesystemPublicKeyStorage) persist() error {
	if err := os.MkdirAll(fs.Dir, 0o700); err != nil {
		return errors.WithStack(err)
	}
	data, err := json.Marshal(fs.entries)
	if err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(os.WriteFile(fs.storageFilePath(), data, 0o600))
}

// NewFilesystemPublicKeyStorageFromLegacy creates a new FilesystemPublicKeyStorage and
// populates it from a LegacyPKCollection stored in the legacy files within the given dir.
// This helper is intended to aid migration and does not retain legacy aggregation behavior.
func NewFilesystemPublicKeyStorageFromLegacy(dir, typeID string) (*FilesystemPublicKeyStorage, error) {
	fs := &FilesystemPublicKeyStorage{
		Dir:    dir,
		TypeID: typeID,
	}
	if err := fs.Load(); err != nil {
		return nil, err
	}
	// Load legacy aggregated storage and import entries for the given typeID
	var agg aggregatedPublicKeyStorage
	if err := agg.Load(dir); err != nil {
		return nil, err
	}
	coll, ok := agg[typeID]
	if !ok || coll == nil {
		return fs, nil
	}
	// Import all JWKS sets and history
	importSet := func(set jwk.Set) {
		if set == nil || set.Len() == 0 {
			return
		}
		for i := range set.Len() {
			k, _ := set.Key(i)
			var kid string
			_ = k.Get("kid", &kid)
			if kid == "" {
				continue
			}
			cloned, cerr := k.Clone()
			if cerr != nil {
				continue
			}
			// Extract timing metadata if present
			var iat, nbf, exp unixtime.Unixtime
			_ = k.Get("iat", &iat)
			_ = k.Get("nbf", &nbf)
			_ = k.Get("exp", &exp)
			entry := PublicKeyEntry{
				KID: kid,
				Key: cloned,
			}
			entry.IssuedAt = iat
			entry.NotBefore = nbf
			entry.ExpiresAt = exp
			// Last write wins for duplicate kids
			fs.entries[kid] = entry
		}
	}
	for _, set := range coll.jwks {
		importSet(set.Set)
	}
	if coll.history.Set != nil {
		importSet(coll.history.Set)
	}
	if err := fs.persist(); err != nil {
		return nil, err
	}
	return fs, nil
}

// NewFilesystemPublicKeyStorageFromStorage creates a new FilesystemPublicKeyStorage
// and populates it from the passed PublicKeyStorage implementation.
func NewFilesystemPublicKeyStorageFromStorage(dir, typeID string, src PublicKeyStorage) (
	*FilesystemPublicKeyStorage, error,
) {
	fs := &FilesystemPublicKeyStorage{
		Dir:     dir,
		TypeID:  typeID,
		entries: make(map[string]PublicKeyEntry),
	}
	// Load source if necessary
	if err := src.Load(); err != nil {
		return nil, err
	}
	list, err := src.GetAll()
	if err != nil {
		return nil, err
	}
	for _, e := range list {
		if e.KID == "" && e.Key != nil {
			var kid string
			_ = e.Key.Get("kid", &kid)
			e.KID = kid
		}
		if e.KID == "" || e.Key == nil {
			continue
		}
		if k, cerr := e.Key.Clone(); cerr == nil {
			e.Key = k
		} else {
			continue
		}
		fs.entries[e.KID] = e
	}
	if err = fs.persist(); err != nil {
		return nil, err
	}
	return fs, nil
}
