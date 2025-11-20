package public

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"
	"github.com/zachmann/go-utils/fileutils"

	log "github.com/go-oidfed/lib/internal"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/unixtime"
)

type jwksSlice []jwx.JWKS

var zeroJWKS jwx.JWKS

// LegacyPKCollection is a collection of public keys, used for signing.
// Deprecated: Only provided for backwards compatibility to provide an easy
// upgrade path from this old implementation to the new one.
type LegacyPKCollection struct {
	// jwksSlice stores the public key JWKS; the order matters!
	// [0] the current JWKS (currently used for signing)
	// [1] the next JWKS (will be used next for signing)
	// [2...n] previous JWKS, where n is the oldest
	jwks                      jwksSlice
	NumberOfOldKeysKeptInJWKS int
	KeepHistory               bool
	history                   jwx.JWKS
}

// LegacyPublicKeyStorage wraps LegacyPKCollection and exposes the PublicKeyStorage
// interface to enable migration to the new FilesystemPublicKeyStorage.
// This should only be used for migrations
type LegacyPublicKeyStorage struct {
	Dir    string
	TypeID string
	coll   *LegacyPKCollection
}

func (l *LegacyPublicKeyStorage) Load() error {
	var agg aggregatedPublicKeyStorage
	if err := agg.Load(l.Dir); err != nil {
		return err
	}
	c, ok := agg[l.TypeID]
	if !ok {
		l.coll = &LegacyPKCollection{}
		return nil
	}
	l.coll = c
	return nil
}

func (l *LegacyPublicKeyStorage) GetAll() (PublicKeyEntryList, error) {
	return l.collectAll(true, true), nil
}

func (l *LegacyPublicKeyStorage) GetRevoked() (PublicKeyEntryList, error) {
	// Legacy format does not track revoked explicitly; return empty
	return PublicKeyEntryList{}, nil
}

func (l *LegacyPublicKeyStorage) GetExpired() (PublicKeyEntryList, error) {
	now := time.Now()
	out := l.collectAll(false, true)
	var expired PublicKeyEntryList
	for _, e := range out {
		if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now) {
			expired = append(expired, e)
		}
	}
	return expired, nil
}

func (l *LegacyPublicKeyStorage) GetHistorical() (PublicKeyEntryList, error) {
	now := time.Now()
	out := l.collectAll(false, true)
	var hist PublicKeyEntryList
	for _, e := range out {
		if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now) {
			hist = append(hist, e)
		}
	}
	return hist, nil
}

func (l *LegacyPublicKeyStorage) GetActive() (PublicKeyEntryList, error) {
	now := time.Now()
	out := l.collectAll(false, false)
	var active PublicKeyEntryList
	for _, e := range out {
		if !e.NotBefore.IsZero() && now.Before(e.NotBefore.Time) {
			continue
		}
		if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now) {
			continue
		}
		active = append(active, e)
	}
	return active, nil
}

func (l *LegacyPublicKeyStorage) GetValid() (PublicKeyEntryList, error) {
	// In legacy, valid = all keys not expired
	now := time.Now()
	list := l.collectAll(true, false)
	var valid PublicKeyEntryList
	for _, e := range list {
		if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now) {
			continue
		}
		valid = append(valid, e)
	}
	return valid, nil
}

func (l *LegacyPublicKeyStorage) Add(key PublicKeyEntry) error { return errors.New("unsupported") }
func (l *LegacyPublicKeyStorage) AddAll(keys []PublicKeyEntry) error {
	return errors.New("unsupported")
}
func (l *LegacyPublicKeyStorage) Update(kid string, data UpdateablePublicKeyMetadata) error {
	return errors.New("unsupported")
}
func (l *LegacyPublicKeyStorage) Delete(kid string) error         { return errors.New("unsupported") }
func (l *LegacyPublicKeyStorage) Revoke(kid, reason string) error { return errors.New("unsupported") }

func (l *LegacyPublicKeyStorage) Get(kid string) (*PublicKeyEntry, error) {
	list := l.collectAll(true, true)
	for _, e := range list {
		if e.KID == kid {
			return &e, nil
		}
	}
	return nil, nil
}

// collectAll flattens legacy JWKS (current, next, olds) and history into PublicKeyEntryList
func (l *LegacyPublicKeyStorage) collectAll(includeNext, includeOlds bool) PublicKeyEntryList {
	if l.coll == nil {
		return PublicKeyEntryList{}
	}
	var sets []jwx.JWKS
	if len(l.coll.jwks) > 0 {
		// current
		sets = append(sets, l.coll.jwks[0])
	}
	if includeNext && len(l.coll.jwks) > 1 {
		sets = append(sets, l.coll.jwks[1])
	}
	if includeOlds && len(l.coll.jwks) > 2 {
		sets = append(sets, l.coll.jwks[2:]...)
	}
	if l.coll.history.Set != nil {
		sets = append(sets, l.coll.history)
	}
	var out PublicKeyEntryList
	for _, s := range sets {
		for i := range s.Len() {
			k, _ := s.Key(i)
			var kid string
			_ = k.Get("kid", &kid)
			if kid == "" {
				continue
			}
			cloned, cerr := k.Clone()
			if cerr != nil {
				continue
			}
			var iatF, nbfF, expF float64
			_ = k.Get("iat", &iatF)
			_ = k.Get("nbf", &nbfF)
			_ = k.Get("exp", &expF)
			var iat, nbf, exp unixtime.Unixtime
			if iatF != 0 {
				sec, dec := math.Modf(iatF)
				iat = unixtime.Unixtime{Time: time.Unix(int64(sec), int64(dec*(1e9)))}
			}
			if nbfF != 0 {
				sec, dec := math.Modf(nbfF)
				nbf = unixtime.Unixtime{Time: time.Unix(int64(sec), int64(dec*(1e9)))}
			}
			if expF != 0 {
				sec, dec := math.Modf(expF)
				exp = unixtime.Unixtime{Time: time.Unix(int64(sec), int64(dec*(1e9)))}
			}
			out = append(
				out, PublicKeyEntry{
					KID:                         kid,
					Key:                         cloned,
					IssuedAt:                    iat,
					NotBefore:                   nbf,
					UpdateablePublicKeyMetadata: UpdateablePublicKeyMetadata{ExpiresAt: exp},
				},
			)
		}
	}
	return out
}

// MarshalJSON implements the json.Marshaler interface
func (pks LegacyPKCollection) MarshalJSON() ([]byte, error) {
	return json.Marshal(pks.jwks)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (pks *LegacyPKCollection) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &pks.jwks)
}

func (pks *LegacyPKCollection) setCurrentJWKS(current jwx.JWKS) {
	if len(pks.jwks) == 0 {
		pks.jwks = append(pks.jwks, current)
		return
	}
	pks.jwks[0] = current
}

func (pks *LegacyPKCollection) addCurrentJWK(current jwk.Key) {
	if len(pks.jwks) == 0 {
		set := jwx.NewJWKS()
		_ = set.AddKey(current)
		pks.jwks = jwksSlice{set}
		return
	}
	_ = pks.jwks[0].AddKey(current)
}

func (pks *LegacyPKCollection) setNextJWKS(next jwx.JWKS) {
	if len(pks.jwks) == 0 {
		log.Error("error setting next JWKS in LegacyPKCollection: no current JWKS set")
		pks.jwks = append(pks.jwks, next)
	}
	if len(pks.jwks) == 1 {
		pks.jwks = append(pks.jwks, next)
		return
	}
	pks.jwks[1] = next
}

func (pks *LegacyPKCollection) addNextJWK(next jwk.Key) {
	if len(pks.jwks) == 0 {
		log.Error("error setting next JWKS in LegacyPKCollection: no current JWKS set")
		set := jwx.NewJWKS()
		_ = set.AddKey(next)
		pks.jwks = jwksSlice{set}
	}
	if len(pks.jwks) == 1 {
		set := jwx.NewJWKS()
		_ = set.AddKey(next)
		pks.jwks = append(pks.jwks, set)
		return
	}
	_ = pks.jwks[1].AddKey(next)
}

func (pks *LegacyPKCollection) pushOldJWKS(old jwx.JWKS) jwx.JWKS {
	l := len(pks.jwks)
	if l < 2 {
		pks.jwks = append(pks.jwks, old)
		return zeroJWKS
	}
	if l == 2 {
		pks.jwks = append(pks.jwks, old)
	} else {
		pks.jwks = slices.Insert(pks.jwks, 2, old)
	}
	if l-2 >= pks.NumberOfOldKeysKeptInJWKS {
		poped := pks.jwks[len(pks.jwks)-1]
		pks.jwks = pks.jwks[:len(pks.jwks)-1]
		if pks.KeepHistory {
			if pks.history.Set == nil {
				pks.history = poped
			} else {
				for i := range poped.Len() {
					k, _ := poped.Key(i)
					_ = pks.history.AddKey(k)
				}
			}
		}
		return poped
	}
	return zeroJWKS
}

// rotate rotates the JWKS, the passed JWKS will be set as the next JWKS,
// the previously next JWKS becomes the current JWKS, the previous current JWKS becomes the first old JWKS,
// and all old JWKS are shifted, while the oldest JWKS (
// if it exceeds the number of old JWKS kept) is removed from the collection and returned.
func (pks *LegacyPKCollection) rotate(next jwx.JWKS) jwx.JWKS {
	if len(pks.jwks) == 0 {
		pks.jwks = append(pks.jwks, next)
		return zeroJWKS
	}
	previouslyCurrent := pks.jwks[0]
	old := pks.pushOldJWKS(previouslyCurrent)
	previouslyNext := pks.jwks[1]
	pks.setCurrentJWKS(previouslyNext)
	pks.setNextJWKS(next)
	return old
}

type aggregatedPublicKeyStorage map[string]*LegacyPKCollection

// Load loads the public keys from disk
func (pks *aggregatedPublicKeyStorage) Load(dir string) error {
	data, err := fileutils.ReadFile(jwksFilePath(dir))
	if err != nil {
		log.Warn(err.Error())
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	if err = errors.WithStack(json.Unmarshal(data, pks)); err != nil {
		return err
	}
	for typeID, collection := range *pks {
		data, err = fileutils.ReadFile(jwksHistoryFilePath(dir, typeID))
		if err != nil {
			continue
		}
		if err = errors.WithStack(json.Unmarshal(data, &collection.history)); err != nil {
			return err
		}
	}
	return nil
}

// Save saves the public keys to disk
func (pks aggregatedPublicKeyStorage) Save(dir string) error {
	data, err := json.Marshal(pks)
	if err != nil {
		return errors.WithStack(err)
	}
	if err = os.WriteFile(jwksFilePath(dir), data, 0600); err != nil {
		return errors.WithStack(err)
	}
	for typeID, collection := range pks {
		if collection.history.Set == nil || collection.history.Len() == 0 {
			continue
		}
		data, err = json.Marshal(collection.history)
		if err != nil {
			return errors.WithStack(err)
		}
		if err = os.WriteFile(jwksHistoryFilePath(dir, typeID), data, 0600); err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

func jwksFilePath(dir string) string {
	return filepath.Join(dir, "keys.jwks")
}
func jwksHistoryFilePath(dir, typeID string) string {
	return filepath.Join(dir, fmt.Sprintf("%s_history.jwks", typeID))
}
