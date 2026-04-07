package oidfed

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-oidfed/lib/jwx"
)

// =============================================================================
// Test entities for trustmark verification
// These use the existing mock infrastructure from trustmark_test.go
// =============================================================================

// rpWithTrustMark is an RP that has trustmarks assigned
var rpWithTrustMark *mockRP

// rpWithoutTrustMark is an RP that has no trustmarks
var rpWithoutTrustMark *mockRP

func init() {
	// Create an RP with trustmarks
	rpWithTrustMark = newMockRP(
		"https://rp-with-tm.example.com",
		&OpenIDRelyingPartyMetadata{ClientRegistrationTypes: []string{"automatic"}},
	)
	rpWithTrustMark.AddAuthority(taWithTmo.EntityID)

	// Create an RP without trustmarks
	rpWithoutTrustMark = newMockRP(
		"https://rp-without-tm.example.com",
		&OpenIDRelyingPartyMetadata{ClientRegistrationTypes: []string{"automatic"}},
	)
	rpWithoutTrustMark.AddAuthority(taWithTmo.EntityID)

	// Register with the trust anchor
	taWithTmo.RegisterSubordinate(rpWithTrustMark)
	taWithTmo.RegisterSubordinate(rpWithoutTrustMark)
}

// =============================================================================
// Tests for VerifyEntityHasValidTrustmarkByTrustAnchors
// =============================================================================

func TestVerifyEntityHasValidTrustmarkByTrustAnchors(t *testing.T) {
	t.Run("entity not found", func(t *testing.T) {
		failing, err := VerifyEntityHasValidTrustmarkByTrustAnchors(
			"https://nonexistent.example.com",
			"https://trustmarks.org/tm1",
			TrustAnchors{{EntityID: taWithTmo.EntityID}},
		)
		// Should return an error (not a failing verification)
		assert.Nil(t, failing)
		assert.Error(t, err)
	})

	t.Run("entity has no trustmarks", func(t *testing.T) {
		failing, err := VerifyEntityHasValidTrustmarkByTrustAnchors(
			rpWithoutTrustMark.EntityID,
			"https://trustmarks.org/tm1",
			TrustAnchors{{EntityID: taWithTmo.EntityID}},
		)
		// Should return a failing verification error (not a system error)
		assert.Error(t, failing)
		assert.Nil(t, err)
		assert.Contains(t, failing.Error(), "does not have required trust mark")
	})

	t.Run("entity has trustmark but wrong type", func(t *testing.T) {
		// First, let's use tmi1 which has trustmarks but we'll ask for a different type
		failing, err := VerifyEntityHasValidTrustmarkByTrustAnchors(
			tmi1.TrustMarkIssuer.EntityID,
			"https://trustmarks.org/nonexistent-type",
			TrustAnchors{{EntityID: taWithTmo.EntityID}},
		)
		// Should fail because the trustmark type doesn't exist
		assert.Error(t, failing)
		assert.Nil(t, err)
	})
}

// =============================================================================
// Tests for VerifyEntityHasValidTrustmarkByTrustMarkIssuerJWKS
// =============================================================================

func TestVerifyEntityHasValidTrustmarkByTrustMarkIssuerJWKS(t *testing.T) {
	t.Run("entity not found", func(t *testing.T) {
		failing, err := VerifyEntityHasValidTrustmarkByTrustMarkIssuerJWKS(
			"https://nonexistent.example.com",
			"https://trustmarks.org/tm1",
			jwx.JWKS{},
			TrustMarkOwnerSpec{},
		)
		assert.Nil(t, failing)
		assert.Error(t, err)
	})

	t.Run("entity has no trustmarks with empty JWKS", func(t *testing.T) {
		failing, err := VerifyEntityHasValidTrustmarkByTrustMarkIssuerJWKS(
			rpWithoutTrustMark.EntityID,
			"https://trustmarks.org/tm1",
			jwx.JWKS{},
			TrustMarkOwnerSpec{},
		)
		// With empty JWKS, it falls back to trust anchor verification
		// but entity has no trustmarks
		assert.Error(t, failing)
		assert.Nil(t, err)
	})
}

// =============================================================================
// Tests for VerifyEntityHasValidTrustmarks (multiple trustmarks)
// =============================================================================

func TestVerifyEntityHasValidTrustmarks(t *testing.T) {
	t.Run("empty trustmark types list", func(t *testing.T) {
		valid, err := VerifyEntityHasValidTrustmarks(
			rpWithoutTrustMark.EntityID,
			[]string{},
			TrustAnchors{{EntityID: taWithTmo.EntityID}},
		)
		// Empty list should succeed (vacuous truth)
		assert.True(t, valid)
		assert.NoError(t, err)
	})

	t.Run("entity missing required trustmark", func(t *testing.T) {
		valid, err := VerifyEntityHasValidTrustmarks(
			rpWithoutTrustMark.EntityID,
			[]string{"https://trustmarks.org/tm1"},
			TrustAnchors{{EntityID: taWithTmo.EntityID}},
		)
		assert.False(t, valid)
		assert.NoError(t, err) // No system error, just verification failure
	})

	t.Run("entity not found", func(t *testing.T) {
		valid, err := VerifyEntityHasValidTrustmarks(
			"https://nonexistent.example.com",
			[]string{"https://trustmarks.org/tm1"},
			TrustAnchors{{EntityID: taWithTmo.EntityID}},
		)
		assert.False(t, valid)
		assert.Error(t, err)
	})
}

// =============================================================================
// Tests with entities that have trustmarks (using TMI entities)
// =============================================================================

// mockRPWithTrustMarks creates an RP with specific trustmarks for testing
type mockRPWithTrustMarks struct {
	*mockRP
	trustMarks TrustMarkInfos
}

func (rp *mockRPWithTrustMarks) EntityStatementPayload() EntityStatementPayload {
	payload := rp.mockRP.EntityStatementPayload()
	payload.TrustMarks = rp.trustMarks
	return payload
}

func (rp *mockRPWithTrustMarks) EntityConfigurationJWT() ([]byte, error) {
	return rp.EntityStatementSigner.JWT(rp.EntityStatementPayload())
}

func TestVerifyEntityHasValidTrustmarkByTrustAnchors_WithValidTrustmark(t *testing.T) {
	// Create a new RP with a valid trustmark
	baseRP := newMockRP(
		"https://rp-tm-valid.example.com",
		&OpenIDRelyingPartyMetadata{ClientRegistrationTypes: []string{"automatic"}},
	)

	// Issue a trustmark for this RP from tmi1 (using TrustMarkIssuer)
	tmJWT, _, err := tmi1.TrustMarkIssuer.IssueTrustMark("https://trustmarks.org/tm1", baseRP.EntityID)
	require.NoError(t, err)

	// Create RP with the trustmark
	rpWithTM := &mockRPWithTrustMarks{
		mockRP: baseRP,
		trustMarks: TrustMarkInfos{
			{
				TrustMarkType: "https://trustmarks.org/tm1",
				TrustMarkJWT:  tmJWT,
			},
		},
	}

	// Register the entity configuration
	mockEntityConfiguration(rpWithTM.EntityID, rpWithTM)
	rpWithTM.AddAuthority(taWithTmo.EntityID)
	taWithTmo.RegisterSubordinate(rpWithTM.mockRP)

	t.Run("valid trustmark verification", func(t *testing.T) {
		failing, err := VerifyEntityHasValidTrustmarkByTrustAnchors(
			rpWithTM.EntityID,
			"https://trustmarks.org/tm1",
			TrustAnchors{{EntityID: taWithTmo.EntityID, JWKS: taWithTmo.data.JWKS}},
		)
		// Both should be nil for successful verification
		assert.Nil(t, failing)
		assert.Nil(t, err)
	})
}

func TestVerifyEntityHasValidTrustmarkByTrustMarkIssuerJWKS_WithValidTrustmark(t *testing.T) {
	// Create a new RP with a valid trustmark
	baseRP := newMockRP(
		"https://rp-tm-jwks-valid.example.com",
		&OpenIDRelyingPartyMetadata{ClientRegistrationTypes: []string{"automatic"}},
	)

	// Issue a trustmark for this RP from tmi1
	// Note: VerifyExternal requires either a delegation JWT or a TrustMarkOwnerSpec
	// For simple JWKS verification, the trustmark needs delegation or we need to pass a TrustMarkOwnerSpec
	tmJWT, _, err := tmi1.TrustMarkIssuer.IssueTrustMark("https://trustmarks.org/tm1", baseRP.EntityID)
	require.NoError(t, err)

	// Create RP with the trustmark
	rpWithTM := &mockRPWithTrustMarks{
		mockRP: baseRP,
		trustMarks: TrustMarkInfos{
			{
				TrustMarkType: "https://trustmarks.org/tm1",
				TrustMarkJWT:  tmJWT,
			},
		},
	}

	// Register the entity configuration
	mockEntityConfiguration(rpWithTM.EntityID, rpWithTM)

	// Get the issuer's JWKS
	issuerJWKS := tmi1.jwks

	t.Run("trustmark verification with JWKS requires delegation or owner", func(t *testing.T) {
		// VerifyExternal requires delegation JWT when TrustMarkOwner is empty
		// This is expected behavior - trustmarks without delegation need federation verification
		failing, err := VerifyEntityHasValidTrustmarkByTrustMarkIssuerJWKS(
			rpWithTM.EntityID,
			"https://trustmarks.org/tm1",
			issuerJWKS,
			TrustMarkOwnerSpec{},
		)
		// Since the trustmark has no delegation, this should fail verification
		assert.Error(t, failing)
		assert.Nil(t, err)
		assert.Contains(t, failing.Error(), "delegation")
	})

	t.Run("invalid trustmark verification with wrong JWKS", func(t *testing.T) {
		// Use a different JWKS that won't verify the signature
		wrongJWKS := tmi2.jwks
		failing, err := VerifyEntityHasValidTrustmarkByTrustMarkIssuerJWKS(
			rpWithTM.EntityID,
			"https://trustmarks.org/tm1",
			wrongJWKS,
			TrustMarkOwnerSpec{},
		)
		// Verification should fail
		assert.Error(t, failing)
		assert.Nil(t, err)
	})
}

func TestVerifyEntityHasValidTrustmarkByTrustMarkIssuerJWKS_WithDelegatedTrustmark(t *testing.T) {
	// Create a new RP with a delegated trustmark
	baseRP := newMockRP(
		"https://rp-tm-jwks-delegated.example.com",
		&OpenIDRelyingPartyMetadata{ClientRegistrationTypes: []string{"automatic"}},
	)

	// Use the "test" trustmark which has delegation from tmo
	tmJWT, _, err := tmi1.TrustMarkIssuer.IssueTrustMark("https://trustmarks.org/test", baseRP.EntityID)
	require.NoError(t, err)

	// Create RP with the delegated trustmark
	rpWithTM := &mockRPWithTrustMarks{
		mockRP: baseRP,
		trustMarks: TrustMarkInfos{
			{
				TrustMarkType: "https://trustmarks.org/test",
				TrustMarkJWT:  tmJWT,
			},
		},
	}

	// Register the entity configuration
	mockEntityConfiguration(rpWithTM.EntityID, rpWithTM)

	// Get the issuer's JWKS
	issuerJWKS := tmi1.jwks

	t.Run("delegated trustmark verification with JWKS", func(t *testing.T) {
		failing, err := VerifyEntityHasValidTrustmarkByTrustMarkIssuerJWKS(
			rpWithTM.EntityID,
			"https://trustmarks.org/test",
			issuerJWKS,
			TrustMarkOwnerSpec{ID: tmo.EntityID, JWKS: tmoJWKS},
		)
		assert.Nil(t, failing)
		assert.Nil(t, err)
	})
}

func TestVerifyEntityHasValidTrustmarks_MultipleValid(t *testing.T) {
	// Create a new RP with multiple valid trustmarks
	baseRP := newMockRP(
		"https://rp-multi-tm.example.com",
		&OpenIDRelyingPartyMetadata{ClientRegistrationTypes: []string{"automatic"}},
	)

	// Issue trustmarks for this RP from tmi1
	tm1JWT, _, err := tmi1.TrustMarkIssuer.IssueTrustMark("https://trustmarks.org/tm1", baseRP.EntityID)
	require.NoError(t, err)
	tm2JWT, _, err := tmi1.TrustMarkIssuer.IssueTrustMark("https://trustmarks.org/tm2", baseRP.EntityID)
	require.NoError(t, err)

	// Create RP with multiple trustmarks
	rpWithTM := &mockRPWithTrustMarks{
		mockRP: baseRP,
		trustMarks: TrustMarkInfos{
			{
				TrustMarkType: "https://trustmarks.org/tm1",
				TrustMarkJWT:  tm1JWT,
			},
			{
				TrustMarkType: "https://trustmarks.org/tm2",
				TrustMarkJWT:  tm2JWT,
			},
		},
	}

	// Register the entity configuration
	mockEntityConfiguration(rpWithTM.EntityID, rpWithTM)
	rpWithTM.AddAuthority(taWithTmo.EntityID)
	taWithTmo.RegisterSubordinate(rpWithTM.mockRP)

	t.Run("all trustmarks valid", func(t *testing.T) {
		valid, err := VerifyEntityHasValidTrustmarks(
			rpWithTM.EntityID,
			[]string{"https://trustmarks.org/tm1", "https://trustmarks.org/tm2"},
			TrustAnchors{{EntityID: taWithTmo.EntityID, JWKS: taWithTmo.data.JWKS}},
		)
		assert.True(t, valid)
		assert.NoError(t, err)
	})

	t.Run("one trustmark missing", func(t *testing.T) {
		valid, err := VerifyEntityHasValidTrustmarks(
			rpWithTM.EntityID,
			[]string{"https://trustmarks.org/tm1", "https://trustmarks.org/nonexistent"},
			TrustAnchors{{EntityID: taWithTmo.EntityID, JWKS: taWithTmo.data.JWKS}},
		)
		assert.False(t, valid)
		assert.NoError(t, err)
	})
}

// =============================================================================
// Tests for delegated trustmarks
// =============================================================================

func TestVerifyEntityHasValidTrustmark_DelegatedTrustmark(t *testing.T) {
	// Create a new RP with a delegated trustmark
	baseRP := newMockRP(
		"https://rp-delegated-tm.example.com",
		&OpenIDRelyingPartyMetadata{ClientRegistrationTypes: []string{"automatic"}},
	)

	// The "test" trustmark uses delegation - tmi1 has a delegation from tmo
	tmJWT, _, err := tmi1.TrustMarkIssuer.IssueTrustMark("https://trustmarks.org/test", baseRP.EntityID)
	require.NoError(t, err)

	// Create RP with the delegated trustmark
	rpWithTM := &mockRPWithTrustMarks{
		mockRP: baseRP,
		trustMarks: TrustMarkInfos{
			{
				TrustMarkType: "https://trustmarks.org/test",
				TrustMarkJWT:  tmJWT,
			},
		},
	}

	// Register the entity configuration
	mockEntityConfiguration(rpWithTM.EntityID, rpWithTM)
	rpWithTM.AddAuthority(taWithTmo.EntityID)
	taWithTmo.RegisterSubordinate(rpWithTM.mockRP)

	t.Run("delegated trustmark verification", func(t *testing.T) {
		failing, err := VerifyEntityHasValidTrustmarkByTrustAnchors(
			rpWithTM.EntityID,
			"https://trustmarks.org/test",
			TrustAnchors{{EntityID: taWithTmo.EntityID, JWKS: taWithTmo.data.JWKS}},
		)
		assert.Nil(t, failing)
		assert.Nil(t, err)
	})
}

// =============================================================================
// Test TrustMarkIssuer methods directly
// =============================================================================

func TestTrustMarkIssuer_IssueTrustMark(t *testing.T) {
	t.Run("issue trustmark", func(t *testing.T) {
		tmJWT, exp, err := tmi1.TrustMarkIssuer.IssueTrustMark("https://trustmarks.org/tm1", "https://subject.example.com")
		require.NoError(t, err)
		assert.NotEmpty(t, tmJWT)
		assert.NotNil(t, exp) // Should have expiration since spec has lifetime

		// Parse and verify the trustmark
		tm, err := ParseTrustMark([]byte(tmJWT))
		require.NoError(t, err)
		assert.Equal(t, "https://trustmarks.org/tm1", tm.TrustMarkType)
		assert.Equal(t, "https://subject.example.com", tm.Subject)
		assert.Equal(t, tmi1.TrustMarkIssuer.EntityID, tm.Issuer)
	})

	t.Run("unknown trustmark type", func(t *testing.T) {
		_, _, err := tmi1.TrustMarkIssuer.IssueTrustMark("https://trustmarks.org/unknown", "https://subject.example.com")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown trustmark")
	})
}

func TestSelfIssuedTrustMarkIssuer_IssueTrustMark(t *testing.T) {
	t.Run("issue self trustmark", func(t *testing.T) {
		info, err := tmi1.SelfIssuedTrustMarkIssuer.IssueTrustMark("https://trustmarks.org/tm1", tmi1.TrustMarkIssuer.EntityID)
		require.NoError(t, err)
		assert.Equal(t, "https://trustmarks.org/tm1", info.TrustMarkType)
		assert.NotEmpty(t, info.TrustMarkJWT)
	})

	t.Run("unknown trustmark type", func(t *testing.T) {
		_, err := tmi1.SelfIssuedTrustMarkIssuer.IssueTrustMark("https://trustmarks.org/unknown", tmi1.TrustMarkIssuer.EntityID)
		assert.Error(t, err)
	})
}
