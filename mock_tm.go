package oidfed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/unixtime"
)

type mockTMI struct {
	TrustMarkIssuer
	SelfIssuedTrustMarkIssuer
	authorities []string
	jwks        jwx.JWKS
}

func (tmi mockTMI) EntityConfigurationJWT() ([]byte, error) {
	return tmi.TrustMarkIssuer.GeneralJWTSigner.EntityStatementSigner().JWT(tmi.EntityStatementPayload())
}

func (tmi mockTMI) EntityStatementPayload() EntityStatementPayload {
	now := time.Now()
	orgID := fmt.Sprintf("%x", md5.Sum([]byte(tmi.TrustMarkIssuer.EntityID)))
	payload := EntityStatementPayload{
		Issuer:         tmi.TrustMarkIssuer.EntityID,
		Subject:        tmi.TrustMarkIssuer.EntityID,
		AuthorityHints: tmi.authorities,
		IssuedAt:       unixtime.Unixtime{Time: now},
		ExpiresAt:      unixtime.Unixtime{Time: now.Add(time.Second * time.Duration(mockStmtLifetime))},
		JWKS:           tmi.jwks,
		Metadata: &Metadata{
			FederationEntity: &FederationEntityMetadata{
				FederationTrustMarkStatusEndpoint: "TODO", //TODO
				OrganizationName:                  fmt.Sprintf("Organization: %s", orgID[:8]),
			},
		},
	}
	return payload
}

func (tmi *mockTMI) AddAuthority(authorityID string) {
	tmi.authorities = append(tmi.authorities, authorityID)
}

func newMockTrustMarkOwner(entityID string, ownedTrustMarks []OwnedTrustMark) *TrustMarkOwner {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return NewTrustMarkOwner(
		entityID, jwx.NewTrustMarkDelegationSigner(
			jwx.NewSingleKeyVersatileSigner(sk, jwa.ES512()),
		), ownedTrustMarks,
	)
}

func newMockTrustMarkIssuer(entityID string, trustMarkSpecs []SelfIssuedTrustMarkSpec) *mockTMI {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer := jwx.NewTrustMarkSigner(jwx.NewSingleKeyVersatileSigner(sk, jwa.ES512()))
	// Extract base TrustMarkSpec for the general issuer
	baseSpecs := make([]TrustMarkSpec, len(trustMarkSpecs))
	for i, spec := range trustMarkSpecs {
		baseSpecs[i] = spec.TrustMarkSpec
	}
	tmi := NewTrustMarkIssuer(entityID, signer, baseSpecs)
	jwks, err := tmi.JWKS()
	if err != nil {
		panic(err)
	}
	selfIssuedTMI := NewSelfIssuedTrustMarkIssuer(entityID, signer, trustMarkSpecs)
	mock := &mockTMI{
		TrustMarkIssuer:           *tmi,
		SelfIssuedTrustMarkIssuer: *selfIssuedTMI,
		jwks:                      jwks,
	}
	mockEntityConfiguration(mock.TrustMarkIssuer.EntityID, mock)
	return mock
}

func (tmi mockTMI) GetSubordinateInfo() mockSubordinateInfo {
	return mockSubordinateInfo{
		entityID: tmi.TrustMarkIssuer.EntityID,
		jwks:     tmi.jwks,
	}
}
