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

type mockProxy struct {
	EntityID    string
	authorities []string
	jwks        jwks.JWKS
	*EntityStatementSigner
	rpMetadata *OpenIDRelyingPartyMetadata
	opMetadata *OpenIDProviderMetadata
}

func newMockProxy(
	entityID string,
	rp *OpenIDRelyingPartyMetadata, op *OpenIDProviderMetadata,
) *mockProxy {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	op.Issuer = entityID
	p := &mockProxy{
		EntityID:   entityID,
		rpMetadata: rp,
		opMetadata: op,
		EntityStatementSigner: NewEntityStatementSigner(
			keystorage.NewSingleKeyVersatileSigner(sk, jwa.ES512()),
			jwa.ES512(),
		),
		jwks: jwks.KeyToJWKS(sk.Public(), jwa.ES512()),
	}
	mockEntityConfiguration(p.EntityID, p)
	return p
}

func (proxy mockProxy) EntityConfigurationJWT() ([]byte, error) {
	return proxy.EntityStatementSigner.JWT(proxy.EntityStatementPayload())
}

func (proxy mockProxy) EntityStatementPayload() EntityStatementPayload {
	now := time.Now()
	orgID := fmt.Sprintf("%x", md5.Sum([]byte(proxy.EntityID)))
	organizationName := fmt.Sprintf("Organization: %s", orgID[:8])
	proxy.rpMetadata.OrganizationName = organizationName
	proxy.opMetadata.OrganizationName = organizationName
	payload := EntityStatementPayload{
		Issuer:         proxy.EntityID,
		Subject:        proxy.EntityID,
		IssuedAt:       unixtime.Unixtime{Time: now},
		ExpiresAt:      unixtime.Unixtime{Time: now.Add(time.Second * time.Duration(mockStmtLifetime))},
		JWKS:           proxy.jwks,
		Audience:       "",
		AuthorityHints: proxy.authorities,
		Metadata: &Metadata{
			FederationEntity: &FederationEntityMetadata{
				OrganizationName: organizationName,
			},
			RelyingParty:   proxy.rpMetadata,
			OpenIDProvider: proxy.opMetadata,
		},
	}
	return payload
}

func (proxy mockProxy) GetSubordinateInfo() mockSubordinateInfo {
	return mockSubordinateInfo{
		entityID: proxy.EntityID,
		jwks:     proxy.jwks,
	}
}

func (proxy *mockProxy) AddAuthority(authorityID string) {
	proxy.authorities = append(proxy.authorities, authorityID)
}
