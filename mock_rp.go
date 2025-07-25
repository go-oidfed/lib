package oidfed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/go-oidfed/lib/jwks"
	"github.com/go-oidfed/lib/keystorage"
	"github.com/go-oidfed/lib/unixtime"
)

type mockRP struct {
	EntityID    string
	authorities []string
	jwks        jwks.JWKS
	*EntityStatementSigner
	metadata *OpenIDRelyingPartyMetadata
}

func newMockRP(entityID string, metadata *OpenIDRelyingPartyMetadata) *mockRP {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	r := &mockRP{
		EntityID: entityID,
		metadata: metadata,
		EntityStatementSigner: NewEntityStatementSigner(
			keystorage.NewSingleKeyVersatileSigner(sk, jwa.ES512()),
			jwa.ES512(),
		),
		jwks: jwks.KeyToJWKS(sk.Public(), jwa.ES512()),
	}
	mockEntityConfiguration(r.EntityID, r)
	return r
}

func (rp mockRP) EntityConfigurationJWT() ([]byte, error) {
	return rp.EntityStatementSigner.JWT(rp.EntityStatementPayload())
}

func (rp mockRP) EntityStatementPayload() EntityStatementPayload {
	now := time.Now()
	orgID := fmt.Sprintf("%x", md5.Sum([]byte(rp.EntityID)))
	payload := EntityStatementPayload{
		Issuer:         rp.EntityID,
		Subject:        rp.EntityID,
		IssuedAt:       unixtime.Unixtime{Time: now},
		ExpiresAt:      unixtime.Unixtime{Time: now.Add(time.Second * time.Duration(mockStmtLifetime))},
		JWKS:           rp.jwks,
		Audience:       "",
		AuthorityHints: rp.authorities,
		Metadata: &Metadata{
			FederationEntity: &FederationEntityMetadata{
				OrganizationName: fmt.Sprintf("Organization: %s", orgID[:8]),
			},
			RelyingParty: rp.metadata,
		},
	}
	return payload
}

func (rp mockRP) GetSubordinateInfo() mockSubordinateInfo {
	return mockSubordinateInfo{
		entityID: rp.EntityID,
		jwks:     rp.jwks,
	}
}

func (rp *mockRP) AddAuthority(authorityID string) {
	rp.authorities = append(rp.authorities, authorityID)
}
