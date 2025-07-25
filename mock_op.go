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

type mockOP struct {
	EntityID    string
	authorities []string
	jwks        jwks.JWKS
	*EntityStatementSigner
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
	o := &mockOP{
		EntityID: entityID,
		metadata: metadata,
		EntityStatementSigner: NewEntityStatementSigner(
			keystorage.NewSingleKeyVersatileSigner(sk, jwa.ES512()),
			jwa.ES512(),
		),
		jwks: jwks.KeyToJWKS(sk.Public(), jwa.ES512()),
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
