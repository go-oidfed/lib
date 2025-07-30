package oidfed

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/zachmann/go-utils/duration"

	"github.com/go-oidfed/lib/jwx"
)

var tmi1 = newMockTrustMarkIssuer(
	"https://tmi.example.org", []TrustMarkSpec{
		{
			TrustMarkType: "https://trustmarks.org/tm1",
			Lifetime:      duration.DurationOption(time.Hour),
		},
		{
			TrustMarkType: "https://trustmarks.org/tm2",
			Lifetime:      duration.DurationOption(time.Hour),
			Ref:           "https://trustmarks.org/tm2/info",
			LogoURI:       "https://trustmarks.org/tm2/logo",
		},
		{
			TrustMarkType: "https://trustmarks.org/tm3",
			Lifetime:      duration.DurationOption(time.Hour),
		},
		{
			TrustMarkType: "https://trustmarks.org/tm4",
			Lifetime:      duration.DurationOption(time.Hour),
		},
		{
			TrustMarkType: "https://trustmarks.org/tm-delegated",
			Lifetime:      duration.DurationOption(time.Hour),
		},
	},
)
var tmi2 = newMockTrustMarkIssuer(
	"https://tmi2.example.com", []TrustMarkSpec{
		{
			TrustMarkType: "https://trustmarks.org/tm1",
			Ref:           "https://trustmarks.org/tm1/info",
			LogoURI:       "https://trustmarks.org/tm1/logo",
			Extra: map[string]any{
				"foo": "bar",
			},
			IncludeExtraClaimsInInfo: false,
		},
		{
			TrustMarkType: "https://trustmarks.org/tm2",
			Ref:           "https://trustmarks.org/tm2/info",
			LogoURI:       "https://trustmarks.org/tm2/logo",
			Extra: map[string]any{
				"foo": "bar",
			},
			IncludeExtraClaimsInInfo: true,
		},
		{
			TrustMarkType: "https://trustmarks.org/tm-delegated",
			Lifetime:      duration.DurationOption(time.Hour),
		},
	},
)

var tmo = newMockTrustMarkOwner(
	"https://tmo.example.eu", []OwnedTrustMark{
		{
			ID:                 "https://trustmarks.org/tm-delegated",
			DelegationLifetime: 24 * time.Hour,
			Extra: map[string]any{
				"key": "value",
			},
		},
		{
			ID: "https://trustmarks.org/test",
		},
		{
			ID: "https://trustmarks.org/invalid",
		},
		{
			ID: "https://trustmarks.org/other",
		},
	},
)

var taWithTmo = newMockAuthority(
	"https://trustmark.ta.com", EntityStatementPayload{
		TrustMarkOwners: map[string]TrustMarkOwnerSpec{
			"https://trustmarks.org/tm-delegated": {
				ID:   "https://tmo.example.eu",
				JWKS: tmo.JWKS(),
			},
			"https://trustmarks.org/test": {
				ID:   "https://tmo.example.eu",
				JWKS: tmo.JWKS(),
			},
			"https://trustmarks.org/other": {
				ID:   "https://other.owner.org",
				JWKS: rp1.jwks,
			},
		},
		TrustMarkIssuers: AllowedTrustMarkIssuers{
			"https://trustmarks.org/tm1": []string{
				"https://tmi.example.org",
				"https://tmi2.example.org",
			},
			"https://trustmarks.org/tm-delegated": []string{
				"https://tmi.example.org",
			},
			"https://trustmarks.org/test": []string{
				"https://tmi.example.org",
			},
			"https://trustmarks.org/tm4": []string{
				"https://tmi2.example.org",
			},
		},
	},
)

func init() {
	delegation, err := tmo.DelegationJWT("https://trustmarks.org/test", "https://tmi.example.org")
	if err != nil {
		panic(err)
	}
	tmi1.AddTrustMark(
		TrustMarkSpec{
			TrustMarkType: "https://trustmarks.org/test",
			Lifetime:      duration.DurationOption(time.Hour),
			DelegationJWT: string(delegation),
		},
	)

	taWithTmo.RegisterSubordinate(tmi1)
	taWithTmo.RegisterSubordinate(tmi2)
}

func TestTrustMarkOwner_DelegationJWT(t *testing.T) {
	tests := []struct {
		name             string
		trustMarkType    string
		sub              string
		lifetime         time.Duration
		expectedLifetime time.Duration
		errExpected      bool
	}{
		{
			name:          "no lifetime",
			trustMarkType: "https://trustmarks.org/test",
			sub:           "https://example.org",
			errExpected:   false,
		},
		{
			name:             "default tmo lifetime",
			trustMarkType:    "https://trustmarks.org/tm-delegated",
			sub:              "https://example.org",
			expectedLifetime: tmo.ownedTrustMarks["https://trustmarks.org/tm-delegated"].DelegationLifetime,
			errExpected:      false,
		},
		{
			name:             "custom lifetime lifetime",
			trustMarkType:    "https://trustmarks.org/tm-delegated",
			sub:              "https://example.org",
			lifetime:         time.Minute,
			expectedLifetime: time.Minute,
			errExpected:      false,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				var delegationJWT []byte
				var err error
				if test.lifetime == 0 {
					delegationJWT, err = tmo.DelegationJWT(test.trustMarkType, test.sub)
				} else {
					delegationJWT, err = tmo.DelegationJWT(test.trustMarkType, test.sub, test.lifetime)
				}
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but got error")
					return
				} else if test.errExpected {
					t.Errorf("expected error, but did not get error")
					return
				}
				delegation, err := parseDelegationJWT(delegationJWT)
				if err != nil {
					t.Errorf("could not parse the produced delegation JWT: %v", err)
					return
				}
				if delegation.TrustMarkType != test.trustMarkType {
					t.Errorf(
						"parsed delegation JWT does not have matching ids: '%s' vs '%s'", test.trustMarkType,
						delegation.TrustMarkType,
					)
					return
				}
				if delegation.Subject != test.sub {
					t.Errorf(
						"parsed delegation JWT does not have matching subjects: '%s' vs '%s'", test.sub,
						delegation.Subject,
					)
					return
				}
				if test.expectedLifetime == 0 {
					if delegation.ExpiresAt != nil && !delegation.ExpiresAt.IsZero() {
						t.Errorf("delegation jwt should not expire")
						return
					}
				} else {
					if delegation.ExpiresAt == nil || delegation.ExpiresAt.Sub(delegation.IssuedAt.Time) != test.
						expectedLifetime {
						t.Errorf("delegation jwt expiration wrong")
						return
					}
				}
				for k, v := range tmo.ownedTrustMarks[test.trustMarkType].Extra {
					if vv := delegation.Extra[k]; vv != v {
						t.Errorf("extra key-value '%s: %s' not correct in delegation jwt: '%s'", k, v, vv)
						return
					}
				}
				if err = delegation.VerifyExternal(tmo.JWKS()); err != nil {
					t.Errorf("error verifying issued delegation jwt: %v", err)
					return
				}
			},
		)
	}
}

func TestDelegationJWT_VerifyExternal(t *testing.T) {
	correctJWKS := jwx.NewJWKS()
	if err := json.Unmarshal(
		[]byte(`{"keys":[{"alg":"ES512","crv":"P-521","kid":"bjQ4ZO1kfWr-cxi-_tU9bKTWwG6XoUwnSW6M5food_U","kty":"EC","use":"sig","x":"AKj5_1MgsEFKCSNN4UyDqQP2wanr9ZD1Q1eBUGJ1BJej8MTQnRkDPRY_35Ctae8bxoj2fxZMufXnWAuVxERelwzL","y":"AObqfUE1k0YIlO1qe-5D8CcTWxZn6OIXC3s_cPrug69sM580aCtug7vEdaBcfNY8RGTwUV1hMxqvOTsQsROrrXG2"}]}`),
		&correctJWKS,
	); err != nil {
		t.Error(err)
	}
	wrongKey := tmo.JWKS()
	tests := []struct {
		name        string
		jwks        jwx.JWKS
		data        []byte
		errExpected bool
	}{
		{
			name:        "correct",
			jwks:        correctJWKS,
			data:        []byte(`eyJhbGciOiJFUzUxMiIsImtpZCI6ImJqUTRaTzFrZldyLWN4aS1fdFU5YktUV3dHNlhvVXduU1c2TTVmb29kX1UiLCJ0eXAiOiJ0cnVzdC1tYXJrLWRlbGVnYXRpb24rand0In0.eyJpYXQiOjE3MTYzODI3NTAuMjcyNTM4MiwiaWQiOiJodHRwczovL3RydXN0bWFya3Mub3JnL3Rlc3QiLCJpc3MiOiJodHRwczovL3Rtby5leGFtcGxlLmV1Iiwic3ViIjoiZm9vYmFyIn0.AE9jSYFV8ZCk5ZFOJbei6bqdG2ASOj8dFDCHfEjRfDu_m8_S3-FPehuYFQAdF45xbcnD1Gk_fIkEoI5LCmeFtTrmAbM2dXyuR7whikyMJZ_tdtwHOsEcZTHTalEvn8dYKY6_GU5POfFmtalH6cTwtQLYx7YH3mb9sBQDnLcd8AA1eMSi`),
			errExpected: false,
		},
		{
			name:        "wrong signature",
			jwks:        correctJWKS,
			data:        []byte(`eyJhbGciOiJFUzUxMiIsImtpZCI6ImJqUTRaTzFrZldyLWN4aS1fdFU5YktUV3dHNlhvVXduU1c2TTVmb29kX1UiLCJ0eXAiOiJ0cnVzdC1tYXJrLWRlbGVnYXRpb24rand0In0.eyJpYXQiOjE3MTYzODI3NTAuMjcyNTM4MiwiaWQiOiJodHRwczovL3RydXN0bWFya3Mub3JnL3Rlc3QiLCJpc3MiOiJodHRwczovL3Rtby5leGFtcGxlLmV1Iiwic3ViIjoiZm9vYmFyIn0.AE9jSYFV8ZCk5ZFOJbei6bqdG2ASOj8dFDCHfEjRfDu_m8_S3-FPehuYFQAdF45xbcnD1Gk_fIkEoI5LCmeFtTrmAbM2dXyuR7whikyMJZ_tdtwHOsEcZTHTalEvn8dYKY6_GU5POfFmtalH6cTwtQLYx7YH3mb9sBQDnLcd8AA1eMSr`),
			errExpected: true,
		},
		{
			name:        "wrong key",
			jwks:        wrongKey,
			data:        []byte(`eyJhbGciOiJFUzUxMiIsImtpZCI6ImJqUTRaTzFrZldyLWN4aS1fdFU5YktUV3dHNlhvVXduU1c2TTVmb29kX1UiLCJ0eXAiOiJ0cnVzdC1tYXJrLWRlbGVnYXRpb24rand0In0.eyJpYXQiOjE3MTYzODI3NTAuMjcyNTM4MiwiaWQiOiJodHRwczovL3RydXN0bWFya3Mub3JnL3Rlc3QiLCJpc3MiOiJodHRwczovL3Rtby5leGFtcGxlLmV1Iiwic3ViIjoiZm9vYmFyIn0.AE9jSYFV8ZCk5ZFOJbei6bqdG2ASOj8dFDCHfEjRfDu_m8_S3-FPehuYFQAdF45xbcnD1Gk_fIkEoI5LCmeFtTrmAbM2dXyuR7whikyMJZ_tdtwHOsEcZTHTalEvn8dYKY6_GU5POfFmtalH6cTwtQLYx7YH3mb9sBQDnLcd8AA1eMSi`),
			errExpected: true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				delegation, err := parseDelegationJWT(test.data)
				if err != nil {
					t.Error(err)
					return
				}
				err = delegation.VerifyExternal(test.jwks)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Error(err)
					return
				} else if test.errExpected {
					t.Errorf("expected error, but did not get error")
					return
				}
			},
		)
	}
}

func TestDelegationJWT_VerifyFederation(t *testing.T) {
	tests := []struct {
		name          string
		trustMarkType string
		errExpected   bool
	}{
		{
			name:          "correct",
			trustMarkType: "https://trustmarks.org/tm-delegated",
			errExpected:   false,
		},
		{
			name:          "correct 2",
			trustMarkType: "https://trustmarks.org/test",
			errExpected:   false,
		},
		{
			name:          "no owner statement",
			trustMarkType: "https://trustmarks.org/invalid",
			errExpected:   true,
		},
		{
			name:          "other owner statement",
			trustMarkType: "https://trustmarks.org/other",
			errExpected:   true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				data, err := tmo.DelegationJWT(test.trustMarkType, "foobar")
				if err != nil {
					t.Error(err)
					return
				}
				delegation, err := parseDelegationJWT(data)
				if err != nil {
					t.Error(err)
					return
				}
				err = delegation.VerifyFederation(taWithTmo.EntityStatementPayload())
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but got error")
					return
				} else if test.errExpected {
					t.Errorf("expected error, but did not get error")
					return
				}
			},
		)
	}
}

func TestTrustMarkIssuer_IssueAndVerifyTrustMark(t *testing.T) {
	tests := []struct {
		name              string
		trustMarkType     string
		tmi               *TrustMarkIssuer
		requestedLifetime time.Duration
		requestLifetime   bool
		expectedLifetime  time.Duration
		ta                *EntityStatementPayload
		errExpectedIssue  bool
		errExpectedVerify bool
	}{
		{
			name:              "normal tm1",
			trustMarkType:     "https://trustmarks.org/tm1",
			tmi:               &tmi1.TrustMarkIssuer,
			expectedLifetime:  time.Hour,
			ta:                taWithTmo.EntityStatementPayload(),
			errExpectedIssue:  false,
			errExpectedVerify: false,
		},
		{
			name:              "custom lifetime tm1",
			trustMarkType:     "https://trustmarks.org/tm1",
			tmi:               &tmi1.TrustMarkIssuer,
			requestLifetime:   true,
			requestedLifetime: 2 * time.Hour,
			expectedLifetime:  2 * time.Hour,
			ta:                taWithTmo.EntityStatementPayload(),
			errExpectedIssue:  false,
			errExpectedVerify: false,
		},
		{
			name:              "unknown tm",
			trustMarkType:     "https://trustmarks.org/unknown",
			tmi:               &tmi1.TrustMarkIssuer,
			ta:                taWithTmo.EntityStatementPayload(),
			errExpectedIssue:  true,
			errExpectedVerify: false,
		},
		{
			name:              "tm3 not in TA",
			trustMarkType:     "https://trustmarks.org/tm3",
			tmi:               &tmi1.TrustMarkIssuer,
			expectedLifetime:  time.Hour,
			ta:                taWithTmo.EntityStatementPayload(),
			errExpectedIssue:  false,
			errExpectedVerify: false,
		},
		{
			name:              "tm4 tmi not in TA",
			trustMarkType:     "https://trustmarks.org/tm4",
			tmi:               &tmi1.TrustMarkIssuer,
			expectedLifetime:  time.Hour,
			ta:                taWithTmo.EntityStatementPayload(),
			errExpectedIssue:  false,
			errExpectedVerify: true,
		},
		{
			name:              "delegation no delegation jwt",
			trustMarkType:     "https://trustmarks.org/tm-delegated",
			tmi:               &tmi1.TrustMarkIssuer,
			expectedLifetime:  time.Hour,
			ta:                taWithTmo.EntityStatementPayload(),
			errExpectedIssue:  false,
			errExpectedVerify: true,
		},
		{
			name:              "delegation ok",
			trustMarkType:     "https://trustmarks.org/test",
			tmi:               &tmi1.TrustMarkIssuer,
			expectedLifetime:  time.Hour,
			ta:                taWithTmo.EntityStatementPayload(),
			errExpectedIssue:  false,
			errExpectedVerify: false,
		},
		{
			name:              "delegation tmi not in ta",
			trustMarkType:     "https://trustmarks.org/tm-delegated",
			tmi:               &tmi2.TrustMarkIssuer,
			expectedLifetime:  time.Hour,
			ta:                taWithTmo.EntityStatementPayload(),
			errExpectedIssue:  false,
			errExpectedVerify: true,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				var err error
				var info *TrustMarkInfo
				if test.requestLifetime {
					info, err = test.tmi.IssueTrustMark(test.trustMarkType, "foobar", test.requestedLifetime)
				} else {
					info, err = test.tmi.IssueTrustMark(test.trustMarkType, "foobar")
				}
				if err != nil {
					if test.errExpectedIssue {
						return
					}
					t.Error(err)
					return
				}
				if test.errExpectedIssue {
					t.Errorf("expected error, but no error returned")
					return
				}

				tm, err := info.TrustMark()
				if err != nil {
					t.Error(err)
					return
				}
				if test.expectedLifetime == 0 {
					if tm.ExpiresAt != nil && !tm.ExpiresAt.IsZero() {
						t.Errorf("trust mark should not expire")
						return
					}
				} else {
					if tm.ExpiresAt == nil || tm.ExpiresAt.Sub(tm.IssuedAt.Time) != test.
						expectedLifetime {
						t.Errorf("trust mark expiration wrong")
						return
					}
				}

				err = info.VerifyFederation(test.ta)
				if err != nil {
					if test.errExpectedVerify {
						return
					}
					t.Error(err)
					return
				}
				if test.errExpectedVerify {
					t.Errorf("expected error, but no error returned")
					return
				}

			},
		)
	}
}
