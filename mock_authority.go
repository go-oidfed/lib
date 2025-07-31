package oidfed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/unixtime"
)

type mockAuthority struct {
	EntityID      string
	FetchEndpoint string
	ListEndpoint  string
	data          EntityStatementPayload
	*jwx.EntityStatementSigner
	subordinates []mockSubordinateInfo
}

func (a mockAuthority) EntityConfigurationJWT() ([]byte, error) {
	return a.EntityStatementSigner.JWT(a.EntityStatementPayload())
}

func (a mockAuthority) FetchResponse(sub string) ([]byte, error) {
	pay := a.SubordinateEntityStatementPayload(sub)
	return a.EntityStatementSigner.JWT(pay)
}

func (a mockAuthority) Subordinates(_ string) (subordinates []string, err error) {
	for _, sub := range a.subordinates {
		subordinates = append(subordinates, sub.entityID)
	}
	return
}

type mockSubordinateInfo struct {
	entityID string
	jwks     jwx.JWKS
}

type mockSubordinate interface {
	GetSubordinateInfo() mockSubordinateInfo
	AddAuthority(authorityID string)
}

func newMockAuthority(entityID string, data EntityStatementPayload) *mockAuthority {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	data.JWKS, err = jwx.KeyToJWKS(sk.Public(), jwa.ES512())
	if err != nil {
		panic(err)
	}
	data.Issuer = entityID
	data.Subject = entityID
	a := &mockAuthority{
		EntityID:      entityID,
		FetchEndpoint: fmt.Sprintf("%s/fetch", entityID),
		ListEndpoint:  fmt.Sprintf("%s/list", entityID),
		data:          data,
		EntityStatementSigner: jwx.NewEntityStatementSigner(
			jwx.NewSingleKeyVersatileSigner(sk, jwa.ES512()),
		),
	}
	if a.data.Metadata == nil {
		a.data.Metadata = &Metadata{}
	}
	if a.data.Metadata.FederationEntity == nil {
		a.data.Metadata.FederationEntity = &FederationEntityMetadata{}
	}
	a.data.Metadata.FederationEntity.OrganizationName = fmt.Sprintf("Organization %d", mathrand.Int()%100)
	a.data.Metadata.FederationEntity.FederationFetchEndpoint = a.FetchEndpoint
	a.data.Metadata.FederationEntity.FederationListEndpoint = a.ListEndpoint

	mockEntityConfiguration(a.EntityID, a)
	mockFetchEndpoint(a.FetchEndpoint, a)
	mockListEndpoint(a.ListEndpoint, a)

	return a
}

func (a mockAuthority) EntityStatementPayload() *EntityStatementPayload {
	now := time.Now()
	payload := a.data
	payload.IssuedAt = unixtime.Unixtime{Time: now}
	payload.ExpiresAt = unixtime.Unixtime{Time: now.Add(time.Second * time.Duration(mockStmtLifetime))}
	return &payload
}

func (a mockAuthority) SubordinateEntityStatementPayload(subID string) EntityStatementPayload {
	now := time.Now()
	var jwks jwx.JWKS
	for _, s := range a.subordinates {
		if s.entityID == subID {
			jwks = s.jwks
		}
	}
	payload := EntityStatementPayload{
		Issuer:             a.EntityID,
		Subject:            subID,
		IssuedAt:           unixtime.Unixtime{Time: now},
		ExpiresAt:          unixtime.Unixtime{Time: now.Add(time.Second * time.Duration(mockStmtLifetime))},
		JWKS:               jwks,
		MetadataPolicy:     a.data.MetadataPolicy,
		MetadataPolicyCrit: a.data.MetadataPolicyCrit,
		Constraints:        a.data.Constraints,
	}
	return payload
}

func (a mockAuthority) GetSubordinateInfo() mockSubordinateInfo {
	return mockSubordinateInfo{
		entityID: a.EntityID,
		jwks:     a.data.JWKS,
	}
}

func (a *mockAuthority) AddAuthority(authorityID string) {
	a.data.AuthorityHints = append(a.data.AuthorityHints, authorityID)
}

func (a *mockAuthority) RegisterSubordinate(s mockSubordinate) {
	info := s.GetSubordinateInfo()
	a.subordinates = append(a.subordinates, info)
	s.AddAuthority(a.EntityID)
}
