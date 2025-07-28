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

type mockOP struct {
	EntityID    string
	authorities []string
	jwks        jwx.JWKS
	*jwx.EntityStatementSigner
	metadata *OpenIDProviderMetadata
}

func (op mockOP) EntityConfigurationJWT() ([]byte, error) {
	return op.EntityStatementSigner.JWT(op.EntityStatementPayload())
}

func newMockOP(entityID string, metadata *OpenIDProviderMetadata) *mockOP {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	metadata.Issuer = entityID
	jwks, err := jwx.KeyToJWKS(sk.Public(), jwa.ES512())
	if err != nil {
		panic(err)
	}
	o := &mockOP{
		EntityID: entityID,
		metadata: metadata,
		EntityStatementSigner: jwx.NewEntityStatementSigner(
			jwx.NewSingleKeyVersatileSigner(sk, jwa.ES512()),
		),
		jwks: jwks,
	}
	mockEntityConfiguration(o.EntityID, o)
	return o
}

func (op mockOP) EntityStatementPayload() EntityStatementPayload {
	now := time.Now()
	orgID := fmt.Sprintf("%x", md5.Sum([]byte(op.EntityID)))
	payload := EntityStatementPayload{
		Issuer:         op.EntityID,
		Subject:        op.EntityID,
		IssuedAt:       unixtime.Unixtime{Time: now},
		ExpiresAt:      unixtime.Unixtime{Time: now.Add(time.Second * time.Duration(mockStmtLifetime))},
		JWKS:           op.jwks,
		Audience:       "",
		AuthorityHints: op.authorities,
		Metadata: &Metadata{
			FederationEntity: &FederationEntityMetadata{
				OrganizationName: fmt.Sprintf("Organization: %s", orgID[:8]),
			},
			OpenIDProvider: op.metadata,
		},
	}
	return payload
}

func (op mockOP) GetSubordinateInfo() mockSubordinateInfo {
	return mockSubordinateInfo{
		entityID: op.EntityID,
		jwks:     op.jwks,
	}
}

func (op *mockOP) AddAuthority(authorityID string) {
	op.authorities = append(op.authorities, authorityID)
}
