package public

import (
	"bytes"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/unixtime"
)

// PublicKeyStorage defines operations for storing and retrieving public keys
// and their associated validity and revocation metadata.
type PublicKeyStorage interface {
	// Load initializes the PublicKeyStorage and loads the public keys (if necessary)
	Load() error
	// GetAll returns all keys in the storage, including revoked and expired keys.
	GetAll() (PublicKeyEntryList, error)
	// GetRevoked returns all revoked keys in the storage.
	GetRevoked() (PublicKeyEntryList, error)
	// GetExpired returns all expired keys in the storage.
	GetExpired() (PublicKeyEntryList, error)
	// GetHistorical returns all keys in the storage that can no longer be
	// used, i.e. revoked and expired keys.
	GetHistorical() (PublicKeyEntryList, error)
	// GetActive returns all active keys in the storage,
	// i.e., keys that can be used currently,
	// i.e., keys that are not revoked and where the current time is between
	// nbf and exp.
	GetActive() (PublicKeyEntryList, error)
	// GetValid returns all valid keys in the storage,
	// i.e., keys that can be used currently or in the future, i.e., keys that are not expired or revoked.
	GetValid() (PublicKeyEntryList, error)
	// Add adds a new key to the storage; the keyID is used to identify the
	// key. Adding a key whose KID is already in use MUST return a
	// ErrDuplicateKID error, so that no two keys sharing a KID can be stored.
	Add(key PublicKeyEntry) error
	// AddAll adds all the passed PublicKeyEntry to the storage. If any entry
	// collides with an existing KID (or two entries in the batch share a KID),
	// it MUST return an ErrDuplicateKID error and add none of them.
	AddAll(key []PublicKeyEntry) error
	// Update updates an existing PublicKeyEntry
	Update(kid string, data UpdateablePublicKeyMetadata) error
	// Delete deletes a PublicKeyEntry
	Delete(kid string) error
	// Revoke revokes an PublicKeyEntry with the passed reason
	Revoke(kid, reason string) error
	// Get returns a PublicKeyEntry
	Get(kid string) (*PublicKeyEntry, error)
}

// NotFoundError indicates that a requested key identifier was not found.
// It is returned by storage operations when an entry expected to exist
// (e.g., for update, revoke, delete, or get) cannot be located.
type NotFoundError struct {
	KID string
}

func (e NotFoundError) Error() string {
	return "public key not found: " + e.KID
}

// DuplicateKIDError is returned when an attempt is made to store a key whose
// KID is already present in the storage. A KID uniquely identifies a key in a
// JWKS; two keys sharing a KID would produce an invalid entity configuration,
// so the conflicting add is refused rather than silently dropping a key.
type DuplicateKIDError struct {
	KID string
}

func (e DuplicateKIDError) Error() string {
	return "public key already exists for kid: " + e.KID
}

// PublicKeyEntryList is a list of PublicKeyEntry
type PublicKeyEntryList []PublicKeyEntry

// JWKS converts the list into a JWKS, cloning each JWK and annotating it with
// standard fields (iat, nbf, exp) and optional revocation information.
//
// A KID must uniquely identify a key within a JWKS. If two or more entries in
// the list share a KID, only one is published: the winner of the deterministic
// preference order (earliest NotBefore, then earliest IssuedAt, then the one
// appearing first in the list), so the resulting JWKS is always kid-unique
// regardless of source ordering.
func (pks PublicKeyEntryList) JWKS() (jwx.JWKS, error) {
	winner := make(map[string]int, len(pks)) // kid -> index of winning entry
	for i, pk := range pks {
		if pk.KID == "" {
			continue
		}
		w, ok := winner[pk.KID]
		if !ok {
			winner[pk.KID] = i
			continue
		}
		if prefersPKOver(pk, pks[w]) {
			winner[pk.KID] = i
		}
	}
	jwks := jwx.NewJWKS()
	for i, pk := range pks {
		if pk.KID == "" {
			continue
		}
		if winner[pk.KID] != i {
			continue
		}
		k, err := pk.JWK()
		if err != nil {
			return jwx.JWKS{}, err
		}
		_ = jwks.AddKey(k)
	}
	return jwks, nil
}

// prefersPKOver reports whether a is preferred over b as the canonical key for
// a shared KID. Preference is by earliest NotBefore, then earliest IssuedAt.
// nil/unset times are treated as zero so keys without timing metadata lose to
// keys that carry it, keeping selection deterministic and stable.
func prefersPKOver(a, b PublicKeyEntry) bool {
	if t, ok := earlierTiming(a.NotBefore, b.NotBefore); ok {
		return t
	}
	return earlierTimingValue(a.IssuedAt, b.IssuedAt)
}

// earlierTiming reports whether a is earlier than b. It returns (aEarlier, false)
// when the two times are equal or both nil, meaning no preference is expressed.
func earlierTiming(a, b *unixtime.Unixtime) (aEarlier, ok bool) {
	if a == nil || b == nil {
		switch {
		case a == nil && b == nil:
			return false, false
		case a == nil:
			return false, true
		default:
			return true, true
		}
	}
	if a.Unix() == b.Unix() {
		return false, false
	}
	return a.Unix() < b.Unix(), true
}

// earlierTimingValue is like earlierTiming but collapses the "no preference"
// outcome to false, used for the tie-breaking IssuedAt comparison.
func earlierTimingValue(a, b *unixtime.Unixtime) bool {
	t, ok := earlierTiming(a, b)
	if !ok {
		return false
	}
	return t
}

// Filter returns a new list containing entries for which the provided filter
// function returns true.
func (pks PublicKeyEntryList) Filter(filter func(entry PublicKeyEntry) bool) (
	filtered PublicKeyEntryList,
) {
	for _, pk := range pks {
		if filter(pk) {
			filtered = append(filtered, pk)
		}
	}
	return
}

// ByAlg groups entries by their JWK signature algorithm and returns a map
// keyed by jwa.SignatureAlgorithm.
func (pks PublicKeyEntryList) ByAlg() map[jwa.SignatureAlgorithm]PublicKeyEntryList {
	m := make(map[jwa.SignatureAlgorithm]PublicKeyEntryList)
	for _, pk := range pks {
		alg, set := pk.Key.Algorithm()
		if !set {
			continue
		}
		signatureAlg, ok := alg.(jwa.SignatureAlgorithm)
		if !ok {
			continue
		}
		if _, ok = m[signatureAlg]; !ok {
			m[signatureAlg] = make(PublicKeyEntryList, 0)
		}
		m[signatureAlg] = append(m[signatureAlg], pk)
	}
	return m
}

// JWKKey is a wrapper around jwk.Key that implements the json.Unmarshaler
// interface, so that it can be used as a field in a PublicKeyEntry.
type JWKKey struct {
	jwk.Key
}

// MarshalJSON implements the json.Marshaler interface
func (k JWKKey) MarshalJSON() ([]byte, error) {
	return json.Marshal((k.Key))
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (k *JWKKey) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	key, err := jwk.ParseKey(data)
	if err != nil {
		return errors.Wrap(err, "failed to parse jwk")
	}
	k.Key = key
	return nil
}

// PublicKeyEntry holds a public JWK alongside issuance, validity and revocation
// metadata used to determine whether the key is usable.
type PublicKeyEntry struct {
	KID       string             `gorm:"primaryKey;column:kid" json:"kid"`
	Key       JWKKey             `gorm:"serializer:json" json:"key"`
	IssuedAt  *unixtime.Unixtime `json:"iat,omitempty"`
	NotBefore *unixtime.Unixtime `json:"nbf,omitempty"`
	UpdateablePublicKeyMetadata
}

// UpdateablePublicKeyMetadata contains fields that can be updated after
// creation, such as expiration and revocation information.
type UpdateablePublicKeyMetadata struct {
	ExpiresAt *unixtime.Unixtime `json:"exp,omitempty"`
	RevokedAt *unixtime.Unixtime `json:"revoked_at,omitempty"`
	Reason    string             `json:"reason,omitempty"`
}

// JWK returns a cloned jwk.Key annotated with standard JWT fields (iat, nbf,
// exp) and optional revocation information.
func (pk PublicKeyEntry) JWK() (jwk.Key, error) {
	key, err := pk.Key.Clone()
	if err != nil {
		return nil, errors.Wrap(err, "failed to clone key")
	}
	if iat := pk.IssuedAt; iat != nil && !iat.IsZero() {
		err = key.Set("iat", iat)
		if err != nil {
			return nil, errors.Wrap(err, "failed to set iat")
		}
	}
	if nbf := pk.NotBefore; nbf != nil && !nbf.IsZero() {
		err = key.Set("nbf", nbf)
		if err != nil {
			return nil, errors.Wrap(err, "failed to set nbf")
		}
	}
	if exp := pk.ExpiresAt; exp != nil && !exp.IsZero() {
		err = key.Set("exp", exp)
		if err != nil {
			return nil, errors.Wrap(err, "failed to set exp")
		}
	}
	if rvk := pk.RevokedAt; rvk != nil && !rvk.IsZero() && rvk.Unix() != 0 {
		revoked := struct {
			RevokedAt unixtime.Unixtime `json:"revoked_at"`
			Reason    string            `json:"reason,omitempty"`
		}{
			RevokedAt: *rvk,
			Reason:    pk.Reason,
		}
		err = key.Set("revoked", revoked)
		if err != nil {
			return nil, errors.Wrap(err, "failed to set revoked")
		}
	}
	return key, nil
}
