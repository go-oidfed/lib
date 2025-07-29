package jwx

import (
	"encoding/json"
	"os"
	"slices"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zachmann/go-utils/fileutils"
)

type jwksSlice []JWKS

type pkCollection struct {
	// jwksSlice stores the public key JWKS; the order matters!
	// [0] the current JWKS (currently used for signing)
	// [1] the next JWKS (will be used next for signing)
	// [2...n] previous JWKS, where n is the oldest
	jwks                      jwksSlice
	NumberOfOldKeysKeptInJWKS int
}

// MarshalJSON implements the json.Marshaler interface
func (pks pkCollection) MarshalJSON() ([]byte, error) {
	return json.Marshal(pks.jwks)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (pks *pkCollection) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &pks.jwks)
}

func (pks *pkCollection) setCurrentJWKS(current JWKS) {
	if len(pks.jwks) == 0 {
		pks.jwks = append(pks.jwks, current)
		return
	}
	pks.jwks[0] = current
}

func (pks *pkCollection) addCurrentJWK(current jwk.Key) {
	if len(pks.jwks) == 0 {
		set := NewJWKS()
		_ = set.AddKey(current)
		pks.jwks = jwksSlice{set}
		return
	}
	_ = pks.jwks[0].AddKey(current)
}

func (pks *pkCollection) setNextJWKS(next JWKS) {
	if len(pks.jwks) == 0 {
		log.Error("error setting next JWKS in pkCollection: no current JWKS set")
		pks.jwks = append(pks.jwks, next)
	}
	if len(pks.jwks) == 1 {
		pks.jwks = append(pks.jwks, next)
		return
	}
	pks.jwks[1] = next
}

func (pks *pkCollection) addNextJWK(next jwk.Key) {
	if len(pks.jwks) == 0 {
		log.Error("error setting next JWKS in pkCollection: no current JWKS set")
		set := NewJWKS()
		_ = set.AddKey(next)
		pks.jwks = jwksSlice{set}
	}
	if len(pks.jwks) == 1 {
		set := NewJWKS()
		_ = set.AddKey(next)
		pks.jwks = append(pks.jwks, set)
		return
	}
	_ = pks.jwks[1].AddKey(next)
}

func (pks *pkCollection) pushOldJWKS(old JWKS) JWKS {
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
		return poped
	}
	return zeroJWKS
}

// rotate rotates the JWKS, the passed JWKS will be set as the next JWKS,
// the previously next JWKS becomes the current JWKS, the previous current JWKS becomes the first old JWKS,
// and all old JWKS are shifted, while the oldest JWKS (
// if it exceeds the number of old JWKS kept) is removed from the collection and returned.
func (pks *pkCollection) rotate(next JWKS) JWKS {
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

type aggregatedPublicKeyStorage map[string]*pkCollection

// Load loads the public keys from disk
func (pks *aggregatedPublicKeyStorage) Load(filepath string) error {
	data, err := fileutils.ReadFile(filepath)
	if err != nil {
		log.Warn(err.Error())
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	return errors.WithStack(json.Unmarshal(data, pks))
}

// Save saves the public keys to disk
func (pks aggregatedPublicKeyStorage) Save(filepath string) error {
	data, err := json.Marshal(pks)
	if err != nil {
		return errors.WithStack(err)
	}
	if err = os.WriteFile(filepath, data, 0600); err != nil {
		return errors.WithStack(err)
	}
	return nil
}
