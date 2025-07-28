package oidfed

import (
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/zachmann/go-utils/maputils"
	"golang.org/x/crypto/sha3"
	"tideland.dev/go/slices"

	"github.com/go-oidfed/lib/cache"
	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/unixtime"
)

// TrustChain is a slice of *EntityStatements
type TrustChain []*EntityStatement

func (c TrustChain) hash() ([]byte, error) {
	data, err := msgpack.Marshal(c)
	if err != nil {
		return nil, err
	}
	hash := sha3.Sum256(data)
	return hash[:], nil
}

// PathLen returns the path len of a chain as defined by the spec,
// i.e. the number of intermediates
func (c TrustChain) PathLen() int {
	// The chain consists of the following stmts:
	// Subject's Entity Configuration
	// Statement(s) about the the subordinate
	// TA's Entity Configuration
	//
	// Therefore, there are at least 3 statements in the chain; in this case
	// there are no intermediates.
	// The number of intermediates is len()-3
	if len(c) <= 3 {
		return 0
	}
	return len(c) - 3
}

// ExpiresAt returns the expiration time of the TrustChain as a UNIX time stamp
func (c TrustChain) ExpiresAt() unixtime.Unixtime {
	if len(c) == 0 {
		return unixtime.Unixtime{}
	}
	exp := c[0].ExpiresAt
	for i := 1; i < len(c); i++ {
		if e := c[i].ExpiresAt; e.Before(exp.Time) {
			exp = e
		}
	}
	return exp
}

// Metadata returns the final Metadata for this TrustChain,
// i.e. the Metadata of the leaf entity with MetadataPolicies of authorities applied to it.
func (c TrustChain) Metadata() (*Metadata, error) {
	if m, set, err := c.cacheGetMetadata(); err != nil {
		internal.Log(err.Error())
	} else if set {
		return m, nil
	}
	if len(c) == 0 {
		return nil, errors.New("trust chain empty")
	}
	if len(c) == 1 {
		return c[0].Metadata, nil
	}
	metadataPolicies := make([]*MetadataPolicies, len(c))
	critPolicies := make(map[PolicyOperatorName]struct{})
	for i, stmt := range c {
		metadataPolicies[i] = stmt.MetadataPolicy
		for _, mpoc := range stmt.MetadataPolicyCrit {
			critPolicies[mpoc] = struct{}{}
		}
	}
	unsupportedCritPolicies := slices.Subtract(maputils.Keys(critPolicies), OperatorOrder)
	if len(unsupportedCritPolicies) > 0 {
		return nil, errors.Errorf(
			"the following metadata policy operators are critical but not understood: %v",
			unsupportedCritPolicies,
		)
	}

	combinedPolicy, err := MergeMetadataPolicies(metadataPolicies...)
	if err != nil {
		return nil, err
	}
	m := c[0].Metadata
	if m == nil {
		m = &Metadata{}
	}
	final, err := m.ApplyPolicy(combinedPolicy)
	if err != nil {
		return nil, err
	}
	if err = c.cacheSetMetadata(final); err != nil {
		internal.Log(err.Error())
	}
	return final, nil
}

// Messages returns the jwts of the TrustChain
func (c TrustChain) Messages() (msgs JWSMessages) {
	for _, cc := range c {
		msgs = append(msgs, cc.jwtMsg)
	}
	return
}

func (c TrustChain) cacheGetMetadata() (
	metadata *Metadata, set bool, err error,
) {
	hash, err := c.hash()
	if err != nil {
		return nil, false, err
	}
	metadata = &Metadata{}
	set, err = cache.Get(
		cache.Key(cache.KeyTrustChainResolvedMetadata, string(hash)), metadata,
	)
	return
}

func (c TrustChain) cacheSetMetadata(metadata *Metadata) error {
	hash, err := c.hash()
	if err != nil {
		return err
	}
	return cache.Set(
		cache.Key(cache.KeyTrustChainResolvedMetadata, string(hash)), metadata,
		unixtime.Until(c.ExpiresAt()),
	)
}
