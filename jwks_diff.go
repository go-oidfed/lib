package oidfed

import (
	"github.com/scylladb/go-set/strset"

	"github.com/go-oidfed/lib/jwx"
)

// ExtractKIDs extracts all non-empty KIDs from a JWKS into a strset.Set.
func ExtractKIDs(jwks jwx.JWKS) *strset.Set {
	kids := strset.New()
	if jwks.Set == nil {
		return kids
	}
	for _, key := range jwks.All() {
		if kid, ok := key.KeyID(); ok && kid != "" {
			kids.Add(kid)
		}
	}
	return kids
}

// HasJWKSChanged compares two KID sets and returns whether they differ.
// Returns: changed, addedKIDs, removedKIDs.
func HasJWKSChanged(oldKIDs, newKIDs *strset.Set) (bool, []string, []string) {
	removed := strset.Difference(oldKIDs, newKIDs).List()
	added := strset.Difference(newKIDs, oldKIDs).List()
	change := false
	if len(added) > 0 {
		change = true
	} else {
		added = nil
	}
	if len(removed) > 0 {
		change = true
	} else {
		removed = nil
	}
	return change, added, removed
}
