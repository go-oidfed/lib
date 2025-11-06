package oidfed

import (
	"time"

	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/cache"
	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/unixtime"
)

// FederationEntity defines the common behavior for federation entities,
// implemented by both StaticFederationEntity and DynamicFederationEntity.
type FederationEntity interface {
	EntityID() string
	// EntityConfigurationPayload returns the payload for the entity configuration
	EntityConfigurationPayload() (*EntityStatementPayload, error)
	// EntityConfigurationJWT returns the signed entity configuration as a JWT
	EntityConfigurationJWT() ([]byte, error)
	// SignEntityStatement signs the provided entity configuration payload
	SignEntityStatement(payload EntityStatementPayload) ([]byte, error)
}

// FederationLeaf is a type for a leaf entity and holds all relevant information about it; it can also be used to
// create an EntityConfiguration about it or to start OIDC flows
type FederationLeaf struct {
	FederationEntity
	TrustAnchors   TrustAnchors
	oidcROProducer *RequestObjectProducer
}

// DynamicFederationEntity mirrors FederationEntity but exposes all properties
// (except EntityID) as functions of time, enabling time-dependent values.
type DynamicFederationEntity struct {
	ID                    string
	Metadata              func() (*Metadata, error)
	AuthorityHints        func() ([]string, error)
	ConfigurationLifetime func() (time.Duration, error)
	EntityStatementSigner func() (*jwx.EntityStatementSigner, error)
	TrustMarks            func() ([]*EntityConfigurationTrustMarkConfig, error)
	TrustMarkIssuers      func() (AllowedTrustMarkIssuers, error)
	TrustMarkOwners       func() (TrustMarkOwners, error)
	Extra                 func() (map[string]any, []string, error)
}

// EntityID returns the entity ID of the DynamicFederationEntity
func (f DynamicFederationEntity) EntityID() string {
	return f.ID
}

// EntityConfigurationPayload returns an EntityStatementPayload for this DynamicFederationEntity
// resolving all dynamic properties at time.Now().
func (f DynamicFederationEntity) EntityConfigurationPayload() (*EntityStatementPayload, error) {
	now := time.Now()

	var err error
	// Resolve dynamic fields
	metadata := (*Metadata)(nil)
	if f.Metadata != nil {
		metadata, err = f.Metadata()
		if err != nil {
			return nil, err
		}
	}

	var authorityHints []string
	if f.AuthorityHints != nil {
		authorityHints, err = f.AuthorityHints()
		if err != nil {
			return nil, err
		}
	}

	lifetime := time.Duration(0)
	if f.ConfigurationLifetime != nil {
		lifetime, err = f.ConfigurationLifetime()
		if err != nil {
			return nil, err
		}
	}
	if lifetime <= 0 {
		lifetime = defaultEntityConfigurationLifetime
	}

	signer := (*jwx.EntityStatementSigner)(nil)
	if f.EntityStatementSigner != nil {
		signer, err = f.EntityStatementSigner()
		if err != nil {
			return nil, err
		}
	}

	var tms []TrustMarkInfo
	if f.TrustMarks != nil {
		trustMarkConfigs, err := f.TrustMarks()
		if err != nil {
			return nil, err
		}
		tms = make([]TrustMarkInfo, 0, len(trustMarkConfigs))
		for _, tmc := range trustMarkConfigs {
			tm, err := tmc.TrustMarkJWT()
			if err != nil {
				internal.Log(err.Error())
				continue
			}
			tms = append(
				tms, TrustMarkInfo{
					TrustMarkType: tmc.TrustMarkType,
					TrustMarkJWT:  tm,
				},
			)
		}
	}

	var trustMarkIssuers AllowedTrustMarkIssuers
	if f.TrustMarkIssuers != nil {
		trustMarkIssuers, err = f.TrustMarkIssuers()
		if err != nil {
			return nil, err
		}
	}

	var trustMarkOwners TrustMarkOwners
	if f.TrustMarkOwners != nil {
		trustMarkOwners, err = f.TrustMarkOwners()
		if err != nil {
			return nil, err
		}
	}

	var extra map[string]any
	var crits []string
	if f.Extra != nil {
		extra, crits, err = f.Extra()
		if err != nil {
			return nil, err
		}
	}

	if metadata != nil {
		metadata.ApplyInformationalClaimsToFederationEntity()
	}

	var jwks jwx.JWKS
	if signer != nil {
		jwks, err = signer.JWKS()
		if err != nil {
			return nil, err
		}
	}

	return &EntityStatementPayload{
		Issuer:             f.ID,
		Subject:            f.ID,
		IssuedAt:           unixtime.Unixtime{Time: now},
		ExpiresAt:          unixtime.Unixtime{Time: now.Add(lifetime)},
		JWKS:               jwks,
		AuthorityHints:     authorityHints,
		Metadata:           metadata,
		TrustMarks:         tms,
		TrustMarkIssuers:   trustMarkIssuers,
		TrustMarkOwners:    trustMarkOwners,
		CriticalExtensions: crits,
		Extra:              extra,
	}, nil
}

// EntityConfigurationJWT creates and returns the signed jwt for the dynamic entity configuration
func (f DynamicFederationEntity) EntityConfigurationJWT() ([]byte, error) {
	payload, err := f.EntityConfigurationPayload()
	if err != nil {
		return nil, err
	}
	return f.SignEntityStatement(*payload)
}

// SignEntityStatement creates a signed JWT for the given EntityStatementPayload
func (f DynamicFederationEntity) SignEntityStatement(payload EntityStatementPayload) ([]byte, error) {
	if f.EntityStatementSigner == nil {
		return nil, errors.New("no signer function configured")
	}
	signer, err := f.EntityStatementSigner()
	if signer == nil {
		return nil, errors.New("no signer available at current time")
	}
	if err != nil {
		return nil, err
	}
	return signer.JWT(payload)
}

// NewFederationEntity creates a new StaticFederationEntity with the passed properties
func NewFederationEntity(
	entityID string, authorityHints []string, metadata *Metadata,
	signer *jwx.EntityStatementSigner, configurationLifetime time.Duration, extra map[string]any,
) (*StaticFederationEntity, error) {
	if configurationLifetime <= 0 {
		configurationLifetime = defaultEntityConfigurationLifetime
	}
	return &StaticFederationEntity{
		ID:                    entityID,
		Metadata:              metadata,
		AuthorityHints:        authorityHints,
		EntityStatementSigner: signer,
		ConfigurationLifetime: configurationLifetime,
		Extra:                 extra,
	}, nil
}

// NewFederationLeaf creates a new FederationLeaf with the passed properties
func NewFederationLeaf(
	entityID string, authorityHints []string, trustAnchors TrustAnchors, metadata *Metadata,
	signer *jwx.EntityStatementSigner, configurationLifetime time.Duration,
	oidcSigner jwx.VersatileSigner, extra map[string]any,
) (*FederationLeaf, error) {
	fed, err := NewFederationEntity(
		entityID, authorityHints, metadata, signer, configurationLifetime, extra,
	)
	if err != nil {
		return nil, err
	}
	return &FederationLeaf{
		FederationEntity: *fed,
		TrustAnchors:     trustAnchors,
		oidcROProducer:   NewRequestObjectProducer(entityID, oidcSigner, time.Minute),
	}, nil
}

// StaticFederationEntity is a type for an entity participating in federations.
// It holds all relevant information about the federation entity and can be used to create
// an EntityConfiguration about it
type StaticFederationEntity struct {
	ID                    string
	Metadata              *Metadata
	AuthorityHints        []string
	ConfigurationLifetime time.Duration
	*jwx.EntityStatementSigner
	TrustMarks       []*EntityConfigurationTrustMarkConfig
	TrustMarkIssuers AllowedTrustMarkIssuers
	TrustMarkOwners  TrustMarkOwners
	Extra            map[string]any
	CriticalClaims   []string
}

// EntityID returns the entity ID of the StaticFederationEntity
func (f StaticFederationEntity) EntityID() string {
	return f.ID
}

// EntityConfigurationPayload returns an EntityStatementPayload for this
// StaticFederationEntity
func (f StaticFederationEntity) EntityConfigurationPayload() (*EntityStatementPayload, error) {
	return DynamicFederationEntity{
		ID: f.ID,
		Metadata: func() (*Metadata, error) {
			return f.Metadata, nil
		},
		AuthorityHints: func() ([]string, error) {
			return f.AuthorityHints, nil
		},
		ConfigurationLifetime: func() (time.Duration, error) { return f.ConfigurationLifetime, nil },
		EntityStatementSigner: func() (*jwx.EntityStatementSigner, error) {
			return f.EntityStatementSigner, nil
		},
		TrustMarks: func() ([]*EntityConfigurationTrustMarkConfig, error) {
			return f.TrustMarks, nil
		},
		TrustMarkIssuers: func() (AllowedTrustMarkIssuers, error) { return f.TrustMarkIssuers, nil },
		TrustMarkOwners: func() (TrustMarkOwners, error) {
			return f.TrustMarkOwners, nil
		},
		Extra: func() (map[string]any, []string, error) { return f.Extra, f.CriticalClaims, nil },
	}.EntityConfigurationPayload()
}

// EntityConfigurationJWT creates and returns the signed jwt as a []byte for
// the entity's entity configuration
func (f StaticFederationEntity) EntityConfigurationJWT() ([]byte, error) {
	payload, err := f.EntityConfigurationPayload()
	if err != nil {
		return nil, err
	}
	return f.SignEntityStatement(*payload)
}

// SignEntityStatement creates a signed JWT for the given EntityStatementPayload; this function is intended to be
// used on TA/IA
func (f StaticFederationEntity) SignEntityStatement(payload EntityStatementPayload) ([]byte, error) {
	return f.EntityStatementSigner.JWT(payload)
}

// RequestObjectProducer returns the entity's RequestObjectProducer
func (f FederationLeaf) RequestObjectProducer() *RequestObjectProducer {
	return f.oidcROProducer
}

// ResolveOPMetadata resolves and returns OpenIDProviderMetadata for the
// passed issuer url
func (f FederationLeaf) ResolveOPMetadata(issuer string) (*OpenIDProviderMetadata, error) {
	var opm OpenIDProviderMetadata
	set, err := cache.Get(cache.Key(cache.KeyOPMetadata, issuer), &opm)
	if err != nil {
		return nil, err
	}
	if set {
		return &opm, nil
	}
	metadata, err := DefaultMetadataResolver.Resolve(
		apimodel.ResolveRequest{
			Subject:     issuer,
			TrustAnchor: f.TrustAnchors.EntityIDs(),
			EntityTypes: []string{"openid_provider"},
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "no trust chain with valid metadata found")
	}
	return metadata.OpenIDProvider, nil
}
