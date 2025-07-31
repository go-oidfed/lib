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

type mockProxy struct {
	EntityID    string
	authorities []string
	jwks        jwx.JWKS
	*jwx.EntityStatementSigner
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
	jwks, err := jwx.KeyToJWKS(sk.Public(), jwa.ES512())
	if err != nil {
		panic(err)
	}
	p := &mockProxy{
		EntityID:   entityID,
		rpMetadata: rp,
		opMetadata: op,
		EntityStatementSigner: jwx.NewEntityStatementSigner(
			jwx.NewSingleKeyVersatileSigner(sk, jwa.ES512()),
		),
		jwks: jwks,
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
