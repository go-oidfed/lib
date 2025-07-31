package oidfed

import (
	"net/url"
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
	expiration           unixtime.Unixtime
	lastTried            unixtime.Unixtime
	sub                  string
	ownTrustMarkEndpoint string
	ownTrustMarkIssuer   *TrustMarkIssuer
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

	if c.JWT != "" {
		parsed, err := jwt.Parse([]byte(c.JWT))
		if err != nil {
			return err
		}
		exp, _ := parsed.Expiration()
		c.expiration = unixtime.Unixtime{Time: exp}
		c.TrustMarkIssuer, _ = parsed.Issuer()
		internal.Logf("Extracted trust mark issuer: %s", c.TrustMarkIssuer)
		err = parsed.Get("trust_mark_type", &c.TrustMarkType)
		if err != nil {
			return errors.Wrap(err, "trustmark id not found in JWT")
		}
		internal.Logf("Extracted trust mark id: %s\n", c.TrustMarkType)
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
// if needed the trust mark is refreshed using the trust mark issuer's trust mark endpoint
func (c *EntityConfigurationTrustMarkConfig) TrustMarkJWT() (string, error) {
	if !c.Refresh {
		return c.JWT, nil
	}
	if c.JWT != "" && unixtime.Until(c.expiration) > c.MinLifetime.Duration() {
		if unixtime.Until(c.expiration) < c.RefreshGracePeriod.Duration() {
			go c.refresh()
		}
		return c.JWT, nil
	}
	err := c.refresh()
	return c.JWT, err
}

// refresh refreshes the trust mark at the trust mark issuer's trust mark endpoint
func (c *EntityConfigurationTrustMarkConfig) refresh() error {
	if time.Since(c.lastTried.Time) < time.Minute {
		// Only try once a minute to obtain a new trust mark
		return errors.New("only trying to refresh trust mark once a minute")
	}
	c.lastTried = unixtime.Now()
	if c.SelfIssued {
		tmi, err := c.ownTrustMarkIssuer.IssueTrustMark(c.TrustMarkType, c.sub)
		if err != nil {
			return err
		}
		c.JWT = tmi.TrustMarkJWT
		exp := tmi.trustmark.ExpiresAt
		if exp != nil {
			c.expiration = *exp
		} else {
			c.expiration = unixtime.Unixtime{}
		}
		return nil
	}

	var endpoint string
	if c.TrustMarkIssuer == c.sub {
		endpoint = c.ownTrustMarkEndpoint
	} else {
		tmi, err := GetEntityConfiguration(c.TrustMarkIssuer)
		if err != nil {
			return err
		}
		if tmi.Metadata == nil || tmi.Metadata.FederationEntity == nil || tmi.Metadata.
			FederationEntity.FederationTrustMarkEndpoint == "" {
			return errors.New("could not obtain trust mark endpoint of trust mark issuer")
		}
		endpoint = tmi.Metadata.FederationEntity.FederationTrustMarkEndpoint
	}
	params := url.Values{}
	params.Add("trust_mark_type", c.TrustMarkType)
	params.Add("sub", c.sub)
	res, errRes, err := http.Get(endpoint, params, nil)
	if err != nil {
		return err
	}
	if errRes != nil {
		return errRes.Err()
	}
	tm, err := ParseTrustMark(res.Body())
	if err != nil {
		return err
	}
	c.JWT = string(tm.jwtMsg.RawJWT)
	if tm.ExpiresAt != nil {
		c.expiration = *tm.ExpiresAt
	} else {
		c.expiration = unixtime.Unixtime{}
	}
	return nil
}
