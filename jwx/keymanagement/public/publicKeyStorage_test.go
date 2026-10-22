package public

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/unixtime"
)

func newPK(t *testing.T, kid string, nbf, iat *time.Time) PublicKeyEntry {
	t.Helper()
	_, pk, _, err := jwx.GenerateKeyPair(jwa.RS256(), 2048)
	require.NoError(t, err)
	require.NoError(t, pk.Set("kid", kid))

	var nbfU, iatU *unixtime.Unixtime
	if nbf != nil {
		nbfU = &unixtime.Unixtime{Time: *nbf}
	}
	if iat != nil {
		iatU = &unixtime.Unixtime{Time: *iat}
	}
	return PublicKeyEntry{
		KID:       kid,
		Key:       JWKKey{Key: pk},
		IssuedAt:  iatU,
		NotBefore: nbfU,
	}
}

func newMemFS(t *testing.T) *FilesystemPublicKeyStorage {
	t.Helper()
	return &FilesystemPublicKeyStorage{
		Dir:     t.TempDir(),
		TypeID:  "test",
		entries: make(map[string]PublicKeyEntry),
	}
}

func kidsOf(t *testing.T, jwks jwx.JWKS) map[string]bool {
	t.Helper()
	kids := make(map[string]bool)
	for i, k := range jwks.All() {
		_ = i
		kid, _ := k.KeyID()
		kids[kid] = true
	}
	return kids
}

func TestFilesystemPublicKeyStorage_AddRejectsDuplicateKID(t *testing.T) {
	fs := newMemFS(t)
	kid := "kid-1"
	require.NoError(t, fs.Add(newPK(t, kid, nil, nil)))

	err := fs.Add(newPK(t, kid, nil, nil))
	require.Error(t, err)
	var dup DuplicateKIDError
	require.ErrorAs(t, err, &dup)
	assert.Equal(t, kid, dup.KID)
}

func TestFilesystemPublicKeyStorage_AddAll_RejectsExistingAndIntraBatch(t *testing.T) {
	kid := "kid-1"

	// Existing KID in storage.
	fs1 := newMemFS(t)
	require.NoError(t, fs1.Add(newPK(t, kid, nil, nil)))
	err := fs1.AddAll([]PublicKeyEntry{newPK(t, "kid-2", nil, nil), newPK(t, kid, nil, nil)})
	require.Error(t, err)
	var dup DuplicateKIDError
	require.ErrorAs(t, err, &dup)

	// Intra-batch duplicates must be rejected and nothing added.
	fs2 := newMemFS(t)
	err = fs2.AddAll([]PublicKeyEntry{newPK(t, kid, nil, nil), newPK(t, kid, nil, nil)})
	require.Error(t, err)
	require.ErrorAs(t, err, &dup)
	all, gErr := fs2.GetAll()
	require.NoError(t, gErr)
	assert.Len(t, all, 0, "atomic AddAll must not add any key on conflict")

	// A clean batch still works.
	fs3 := newMemFS(t)
	require.NoError(t, fs3.AddAll([]PublicKeyEntry{newPK(t, "a", nil, nil), newPK(t, "b", nil, nil)}))
	all, gErr = fs3.GetAll()
	require.NoError(t, gErr)
	assert.Len(t, all, 2)
}

func TestPublicKeyEntryList_JWKS_DedupesByKID(t *testing.T) {
	now := time.Now()
	ts := func(d time.Duration) *time.Time {
		v := now.Add(d)
		return &v
	}

	shared := "shared-kid"
	other := "other-kid"

	// Two entries claiming the same kid; the one with the earliest nbf wins
	// regardless of list order.
	older := newPK(t, shared, ts(-2*time.Hour), ts(-3*time.Hour))
	newer := newPK(t, shared, ts(-1*time.Hour), ts(-1*time.Hour))
	parent := newPK(t, other, ts(-time.Hour), ts(-2*time.Hour))

	// Put the non-winning (newer) entry first to prove the winner is chosen by
	// timing, not list position.
	j, err := PublicKeyEntryList{newer, parent, older}.JWKS()
	require.NoError(t, err)

	assert.Equal(t, map[string]bool{shared: true, other: true}, kidsOf(t, j), "each kid must appear exactly once")
	assert.Equal(t, 2, j.Len(), "duplicate kid must be collapsed to a single key")

	// The surviving shared-kid key must be the earliest-nbf one (older).
	for i, k := range j.All() {
		_ = i
		kid, _ := k.KeyID()
		if kid != shared {
			continue
		}
		nbfVal, nbfErr := jwk.Get[*unixtime.Unixtime](k, "nbf")
		require.NoError(t, nbfErr, "published key should carry nbf")
		require.NotNil(t, nbfVal)
		assert.Equal(t, older.NotBefore.Time.Unix(), nbfVal.Unix())
	}
}

func TestNewFilesystemPublicKeyStorageFromStorage_RejectsDuplicateKid(t *testing.T) {
	// A source whose entries share a KID claim must fail migration.
	src := &memSource{list: PublicKeyEntryList{
		newPK(t, "dup", nil, nil),
		newPK(t, "dup", nil, nil),
	}}
	_, err := NewFilesystemPublicKeyStorageFromStorage(t.TempDir(), "test", src)
	require.Error(t, err)
	var dup DuplicateKIDError
	require.ErrorAs(t, err, &dup)
	assert.Equal(t, "dup", dup.KID)
}

// memSource is a minimal PublicKeyStorage used to exercise migration.
type memSource struct {
	list PublicKeyEntryList
}

func (m *memSource) Load() error                         { return nil }
func (m *memSource) GetAll() (PublicKeyEntryList, error) { return m.list, nil }
func (m *memSource) GetRevoked() (PublicKeyEntryList, error) {
	return nil, nil
}
func (m *memSource) GetExpired() (PublicKeyEntryList, error) {
	return nil, nil
}
func (m *memSource) GetHistorical() (PublicKeyEntryList, error) { return nil, nil }
func (m *memSource) GetActive() (PublicKeyEntryList, error)     { return nil, nil }
func (m *memSource) GetValid() (PublicKeyEntryList, error)      { return m.list, nil }
func (m *memSource) Add(PublicKeyEntry) error                   { return nil }
func (m *memSource) AddAll([]PublicKeyEntry) error              { return nil }
func (m *memSource) Update(string, UpdateablePublicKeyMetadata) error {
	return nil
}
func (m *memSource) Clear() error { return nil }
func (m *memSource) Delete(string) error {
	return nil
}
func (m *memSource) Revoke(string, string) error { return nil }
func (m *memSource) Get(string) (*PublicKeyEntry, error) {
	return nil, nil
}

var _ PublicKeyStorage = (*memSource)(nil)
