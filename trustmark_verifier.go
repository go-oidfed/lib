package oidfed

import (
	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/jwx"
)

// verifyEntityHasValidTrustmark verifies that the entity has a valid
// trustmark of the given type. Verification is either done by verifying
// the trustmark against a list of trust anchors or by verifying the trustmark
// against the trustmark issuer's jwks.
// The first return value is an error if the trustmark is not present or could
// not be verified.
// The second return value is an error for something else.
func verifyEntityHasValidTrustmark(
	entityID, trustMarkType string,
	trustMarkIssuerJWKS jwx.JWKS, trustMarkOwner TrustMarkOwnerSpec,
	trustAnchors TrustAnchors,
) (error, error) {
	ec, err := GetEntityConfiguration(entityID)
	if err != nil {
		return nil, errors.Wrap(err, "error while obtaining entity configuration")
	}
	tms := ec.TrustMarks
	noTrustMarkError := errors.Errorf("entity does not have required trust mark '%s'", trustMarkType)
	if len(tms) == 0 {
		return noTrustMarkError, nil
	}
	tm := tms.FindByType(trustMarkType)
	if tm == nil {
		return noTrustMarkError, nil
	}
	if trustMarkIssuerJWKS.Set != nil && trustMarkIssuerJWKS.Len() != 0 {
		if err = tm.VerifyExternal(trustMarkIssuerJWKS, trustMarkOwner); err != nil {
			return errors.Wrap(err, "error while verifying trust mark"), nil
		}
		return nil, nil
	}
	for _, ta := range trustAnchors {
		taConfig, err := GetEntityConfiguration(ta.EntityID)
		if err != nil {
			continue
		}
		if err = tm.VerifyFederation(&taConfig.EntityStatementPayload); err == nil {
			return nil, nil
		}
	}
	return errors.New("could not verify required trust mark"), nil
}

// VerifyEntityHasValidTrustmarkByTrustMarkIssuerJWKS verifies that the entity has a valid
// trustmark of the given type. Verification is done by verifying the trustmark
// against the trustmark issuer's jwks.
func VerifyEntityHasValidTrustmarkByTrustMarkIssuerJWKS(
	entityID, trustMarkType string,
	trustMarkIssuerJWKS jwx.JWKS, trustMarkOwner TrustMarkOwnerSpec,
) (error, error) {
	return verifyEntityHasValidTrustmark(entityID, trustMarkType, trustMarkIssuerJWKS, trustMarkOwner, nil)
}

// VerifyEntityHasValidTrustmarkByTrustAnchors verifies that the entity has a valid
// trustmark of the given type. Verification is done by verifying the trustmark
// against a list of trust anchors.
func VerifyEntityHasValidTrustmarkByTrustAnchors(entityID, trustMarkType string, trustAnchors TrustAnchors) (
	error, error,
) {
	return verifyEntityHasValidTrustmark(entityID, trustMarkType, jwx.JWKS{}, TrustMarkOwnerSpec{}, trustAnchors)
}

// VerifyEntityHasValidTrustmarks verifies that the entity has valid
// trustmarks for all the given types.
func VerifyEntityHasValidTrustmarks(
	entityID string, trustMarkTypes []string,
	trustAnchors TrustAnchors,
) (bool, error) {
	for _, trustMarkType := range trustMarkTypes {
		failing, err := VerifyEntityHasValidTrustmarkByTrustAnchors(entityID, trustMarkType, trustAnchors)
		if err != nil || failing != nil {
			return false, err
		}
	}
	return true, nil
}
