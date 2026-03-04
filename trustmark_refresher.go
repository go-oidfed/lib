package oidfed

import (
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/pkg/errors"
	"github.com/zachmann/go-utils/duration"

	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/internal/http"
	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/unixtime"
)

// EntityConfigurationTrustMarkConfig is a type for specifying the configuration of a TrustMark that should be
// included in an EntityConfiguration
type EntityConfigurationTrustMarkConfig struct {
	TrustMarkType        string                  `yaml:"trust_mark_type"`
	TrustMarkIssuer      string                  `yaml:"trust_mark_issuer"`
	SelfIssued           bool                    `yaml:"self_issued"`
	SelfIssuanceSpec     TrustMarkSpec           `yaml:"self_issuance_spec"`
	JWT                  string                  `yaml:"trust_mark_jwt"`
	Refresh              bool                    `yaml:"refresh"`
	MinLifetime          duration.DurationOption `yaml:"min_lifetime"`
	RefreshGracePeriod   duration.DurationOption `yaml:"refresh_grace_period"`
	RefreshRateLimit     duration.DurationOption `yaml:"refresh_rate_limit"`
	expiration           unixtime.Unixtime
	lastTried            unixtime.Unixtime
	sub                  string
	ownTrustMarkEndpoint string
	ownTrustMarkIssuer   *TrustMarkIssuer
	mu                   sync.RWMutex
	refreshing           atomic.Bool
	consecutiveFailures  int
}

// Verify verifies that the EntityConfigurationTrustMarkConfig is correct and also extracts trust mark id and issuer
// if a trust mark jwt is given as well as sets default values
func (c *EntityConfigurationTrustMarkConfig) Verify(
	sub, ownTrustMarkEndpoint string, ownTrustMarkSigner *jwx.TrustMarkSigner,
) error {
	c.sub = sub
	c.ownTrustMarkEndpoint = ownTrustMarkEndpoint
	if c.MinLifetime == 0 {
		c.MinLifetime = duration.DurationOption(10 * time.Second)
	}
	if c.RefreshGracePeriod == 0 {
		c.RefreshGracePeriod = duration.DurationOption(time.Hour)
	}
	if c.RefreshRateLimit == 0 {
		c.RefreshRateLimit = duration.DurationOption(time.Minute)
	}

	if c.JWT != "" {
		parsed, err := jwt.Parse([]byte(c.JWT))
		if err != nil {
			return err
		}
		exp, _ := parsed.Expiration()
		c.expiration = unixtime.Unixtime{Time: exp}
		c.TrustMarkIssuer, _ = parsed.Issuer()
		internal.Logf("TrustMarkRefresher: extracted trust mark issuer: %s", c.TrustMarkIssuer)
		err = parsed.Get("trust_mark_type", &c.TrustMarkType)
		if err != nil {
			return errors.Wrap(err, "trustmark id not found in JWT")
		}
		internal.Logf("TrustMarkRefresher: extracted trust mark id: %s", c.TrustMarkType)
		return nil
	}
	c.Refresh = true
	if c.SelfIssued {
		c.SelfIssuanceSpec.TrustMarkType = c.TrustMarkType
		c.ownTrustMarkIssuer = NewTrustMarkIssuer(
			sub, ownTrustMarkSigner,
			[]TrustMarkSpec{c.SelfIssuanceSpec},
		)
		if c.TrustMarkType == "" {
			return errors.New("trust_mark_type must be provided for self-issued trust marks")
		}
		return nil
	}
	if c.TrustMarkType == "" || c.TrustMarkIssuer == "" {
		return errors.New("either trust_mark_jwt or trust_mark_issuer and trust_mark_type must be specified")
	}
	return nil
}

// TrustMarkJWT returns a trust mark jwt for the linked trust mark,
// if needed the trust mark is refreshed using the trust mark issuer's trust mark endpoint.
// This method is safe for concurrent use.
func (c *EntityConfigurationTrustMarkConfig) TrustMarkJWT() (string, error) {
	// Read current state with read lock
	c.mu.RLock()
	refresh := c.Refresh
	currentJWT := c.JWT
	expiration := c.expiration
	c.mu.RUnlock()

	if !refresh {
		return currentJWT, nil
	}
	if currentJWT != "" && unixtime.Until(expiration) > c.MinLifetime.Duration() {
		if unixtime.Until(expiration) < c.RefreshGracePeriod.Duration() {
			// Use atomic CAS to prevent multiple concurrent background refreshes
			if c.refreshing.CompareAndSwap(false, true) {
				go func() {
					defer c.refreshing.Store(false)
					if err := c.refresh(); err != nil {
						internal.WithError(err).Warn("TrustMarkRefresher: background refresh failed")
					}
				}()
			}
		}
		return currentJWT, nil
	}
	err := c.refresh()

	// Read the updated JWT after refresh
	c.mu.RLock()
	currentJWT = c.JWT
	c.mu.RUnlock()

	return currentJWT, err
}

// refresh refreshes the trust mark at the trust mark issuer's trust mark endpoint.
// It implements rate limiting with exponential backoff on consecutive failures.
func (c *EntityConfigurationTrustMarkConfig) refresh() error {
	// Calculate backoff duration with exponential increase
	c.mu.RLock()
	baseDelay := c.RefreshRateLimit.Duration()
	failures := c.consecutiveFailures
	lastTried := c.lastTried
	c.mu.RUnlock()

	// Exponential backoff: base * 2^failures, capped at 1 hour
	backoffDelay := baseDelay
	if failures > 0 {
		backoffDelay = baseDelay * time.Duration(1<<min(failures, 6)) // Cap at 2^6 = 64x
		if backoffDelay > time.Hour {
			backoffDelay = time.Hour
		}
	}

	if time.Since(lastTried.Time) < backoffDelay {
		return errors.Errorf(
			"rate limited: next refresh allowed in %v",
			backoffDelay-time.Since(lastTried.Time),
		)
	}

	// Update lastTried timestamp
	c.mu.Lock()
	c.lastTried = unixtime.Now()
	c.mu.Unlock()

	// Perform the actual refresh
	var newJWT string
	var newExpiration unixtime.Unixtime
	var err error

	if c.SelfIssued {
		newJWT, newExpiration, err = c.refreshSelfIssued()
	} else {
		newJWT, newExpiration, err = c.refreshExternal()
	}

	// Update state with write lock
	c.mu.Lock()
	defer c.mu.Unlock()

	if err != nil {
		c.consecutiveFailures++
		return err
	}

	// Success - update JWT and reset backoff
	c.JWT = newJWT
	c.expiration = newExpiration
	c.consecutiveFailures = 0
	return nil
}

// refreshSelfIssued handles self-issued trust mark refresh
func (c *EntityConfigurationTrustMarkConfig) refreshSelfIssued() (string, unixtime.Unixtime, error) {
	tmi, err := c.ownTrustMarkIssuer.IssueTrustMark(c.TrustMarkType, c.sub)
	if err != nil {
		return "", unixtime.Unixtime{}, err
	}
	exp := unixtime.Unixtime{}
	if tmi.trustmark.ExpiresAt != nil {
		exp = *tmi.trustmark.ExpiresAt
	}
	return tmi.TrustMarkJWT, exp, nil
}

// refreshExternal handles external trust mark issuer refresh
func (c *EntityConfigurationTrustMarkConfig) refreshExternal() (string, unixtime.Unixtime, error) {
	var endpoint string
	if c.TrustMarkIssuer == c.sub {
		endpoint = c.ownTrustMarkEndpoint
	} else {
		tmi, err := GetEntityConfiguration(c.TrustMarkIssuer)
		if err != nil {
			return "", unixtime.Unixtime{}, err
		}
		if tmi.Metadata == nil || tmi.Metadata.FederationEntity == nil || tmi.Metadata.
			FederationEntity.FederationTrustMarkEndpoint == "" {
			return "", unixtime.Unixtime{}, errors.New("could not obtain trust mark endpoint of trust mark issuer")
		}
		endpoint = tmi.Metadata.FederationEntity.FederationTrustMarkEndpoint
	}
	params := url.Values{}
	params.Add("trust_mark_type", c.TrustMarkType)
	params.Add("sub", c.sub)
	res, errRes, err := http.Get(endpoint, params, nil)
	if err != nil {
		return "", unixtime.Unixtime{}, err
	}
	if errRes != nil {
		return "", unixtime.Unixtime{}, errRes.Err()
	}
	tm, err := ParseTrustMark(res.Body())
	if err != nil {
		return "", unixtime.Unixtime{}, err
	}
	exp := unixtime.Unixtime{}
	if tm.ExpiresAt != nil {
		exp = *tm.ExpiresAt
	}
	return string(tm.jwtMsg.RawJWT), exp, nil
}
