package oidfed

import (
	"encoding/json"

	"github.com/google/go-querystring/query"
	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/internal/http"
	"github.com/go-oidfed/lib/internal/jwx"
	"github.com/go-oidfed/lib/oidfedconst"
)

// MetadataResolver is type for resolving the metadata from a StartingEntity to
// one or multiple TrustAnchors
type MetadataResolver interface {
	Resolve(request apimodel.ResolveRequest) (*Metadata, error)
	ResolveResponsePayload(request apimodel.ResolveRequest) (ResolveResponsePayload, error)
	ResolvePossible(request apimodel.ResolveRequest) (validConfirmed, invalidConfirmed bool)
}

// DefaultMetadataResolver is the default MetadataResolver used within the
// library to resolve Metadata
var DefaultMetadataResolver MetadataResolver = LocalMetadataResolver{}

// LocalMetadataResolver is a MetadataResolver that resolves trust chains and
// evaluates metadata policies to obtain the final Metadata; it does not use
// a resolve endpoint
type LocalMetadataResolver struct{}

// Resolve implements the MetadataResolver interface
func (r LocalMetadataResolver) Resolve(req apimodel.ResolveRequest) (*Metadata, error) {
	res, _, err := r.resolveResponsePayloadWithoutTrustMarks(req)
	if err != nil {
		return nil, err
	}
	return res.Metadata, nil
}

func (LocalMetadataResolver) resolveResponsePayloadWithoutTrustMarks(
	req apimodel.ResolveRequest,
) (
	res ResolveResponsePayload, chain TrustChain, err error,
) {
	tr := TrustResolver{
		TrustAnchors:   NewTrustAnchorsFromEntityIDs(req.TrustAnchor...),
		StartingEntity: req.Subject,
		Types:          req.EntityTypes,
	}
	chains := tr.ResolveToValidChains()
	if len(chains) == 0 {
		err = errors.New("no trust chain found")
		return
	}
	chains = chains.SortAsc(TrustChainScoringPathLen)
	for _, chain = range chains {
		m, err := chain.Metadata()
		if err == nil {
			res.TrustChain = chain.Messages()
			res.Metadata = m
			res.TrustAnchor = chain[len(chain)-1].Issuer
			return res, chain, nil
		}
	}
	err = errors.New("no trust chain with valid metadata found")
	return
}

// ResolveResponsePayload implements the MetadataResolver interface
func (r LocalMetadataResolver) ResolveResponsePayload(req apimodel.ResolveRequest) (
	res ResolveResponsePayload, err error,
) {
	var chain TrustChain
	res, chain, err = r.resolveResponsePayloadWithoutTrustMarks(req)
	if err != nil {
		return
	}
	if len(chain) == 0 {
		return res, errors.New("no trust chain returned")
	}
	res.TrustMarks = chain[0].TrustMarks.VerifiedFederation(&chain[len(chain)-1].EntityStatementPayload)
	return
}

// ResolvePossible implements the MetadataResolver interface
func (LocalMetadataResolver) ResolvePossible(req apimodel.ResolveRequest) (bool, bool) {
	tr := TrustResolver{
		TrustAnchors:   NewTrustAnchorsFromEntityIDs(req.TrustAnchor...),
		StartingEntity: req.Subject,
		Types:          req.EntityTypes,
	}
	chains := tr.ResolveToValidChains()
	valid := len(chains) > 0
	return valid, !valid
}

// SimpleRemoteMetadataResolver is a MetadataResolver that utilizes a given
// ResolveEndpoint
type SimpleRemoteMetadataResolver struct {
	ResolveEndpoint string
}

const (
	resolveStatusUnknown = iota
	resolveStatusValid
	resolveStatusOnlyValidTrustChain
	resolveStatusInvalid
	resolveStatusNotAcceptable
)

// ResolveResponse returns the ResolveResponse from a response endpoint
func (r SimpleRemoteMetadataResolver) ResolveResponse(req apimodel.ResolveRequest) (
	*ResolveResponse, int, error,
) {
	// Default to unknown until we positively parse a valid response
	var resolveStatus = resolveStatusUnknown
	params, err := query.Values(req)
	if err != nil {
		return nil, resolveStatus, errors.WithStack(err)
	}
	res, errRes, err := http.Get(r.ResolveEndpoint, params, nil)
	if err != nil {
		return nil, resolveStatus, err
	}
	if errRes != nil {
		switch errRes.Error {
		case InvalidSubject, InvalidTrustAnchor:
			resolveStatus = resolveStatusNotAcceptable
		case InvalidTrustChain:
			resolveStatus = resolveStatusInvalid
		case InvalidMetadata:
			resolveStatus = resolveStatusOnlyValidTrustChain
		default:
			resolveStatus = resolveStatusUnknown
		}
		return nil, resolveStatus, nil
	}
	rres, err := ParseResolveResponse(res.Body())
	if err != nil {
		// Keep status at unknown for parse/format errors
		return nil, resolveStatus, err
	}
	resolveStatus = resolveStatusValid
	return rres, resolveStatus, nil
}

// Resolve implements the MetadataResolver interface
func (r SimpleRemoteMetadataResolver) Resolve(req apimodel.ResolveRequest) (*Metadata, error) {
	res, resStatus, err := r.ResolveResponse(req)
	if err != nil {
		return nil, err
	}
	if resStatus != resolveStatusValid {
		return nil, errors.New("no positive resolve response from remote resolver")
	}
	return res.Metadata, nil
}

// ResolveResponsePayload implements the MetadataResolver interface
func (r SimpleRemoteMetadataResolver) ResolveResponsePayload(req apimodel.ResolveRequest) (
	ResolveResponsePayload, error,
) {
	res, resStatus, err := r.ResolveResponse(req)
	if err != nil {
		return ResolveResponsePayload{}, err
	}
	if resStatus != resolveStatusValid {
		return ResolveResponsePayload{}, errors.New("no positive resolve response from remote resolver")
	}
	return res.ResolveResponsePayload, nil
}

// ResolvePossible implements the MetadataResolver interface
func (r SimpleRemoteMetadataResolver) ResolvePossible(req apimodel.ResolveRequest) (bool, bool) {
	_, resStatus, err := r.ResolveResponse(req)
	if err != nil {
		internal.Log(err.Error())
		return false, true
	}
	switch resStatus {
	case resolveStatusValid, resolveStatusOnlyValidTrustChain:
		return true, false
	case resolveStatusInvalid:
		return false, true
	default:
		return false, false
	}
}

// ParseResolveResponse parses a jwt into a ResolveResponse
func ParseResolveResponse(body []byte) (*ResolveResponse, error) {
	r, err := jwx.Parse(body)
	if err != nil {
		return nil, err
	}
	if !r.VerifyType(oidfedconst.JWTTypeResolveResponse) {
		return nil, errors.Errorf("response does not have '%s' JWT type", oidfedconst.JWTTypeResolveResponse)
	}
	var res ResolveResponse
	payload := r.Payload()
	// Guard against null payloads which would cause a nil deref when used by callers
	if string(payload) == "null" {
		return nil, errors.New("invalid resolve response: null payload")
	}
	if err = json.Unmarshal(payload, &res); err != nil {
		return nil, err
	}
	return &res, err
}

// SmartRemoteMetadataResolver is a MetadataResolver that utilizes remote
// resolve endpoints. It will iterate through the resolve endpoints of the
// given TrustAnchors and stop if one is successful,
// if no resolve endpoint is successful, local resolving is used
type SmartRemoteMetadataResolver struct{}

// Resolve implements the MetadataResolver interface
func (r SmartRemoteMetadataResolver) Resolve(req apimodel.ResolveRequest) (*Metadata, error) {
	res, err := r.ResolveResponsePayload(req)
	if err != nil {
		return nil, err
	}
	return res.Metadata, nil
}

// ResolveResponsePayload implements the MetadataResolver interface
func (SmartRemoteMetadataResolver) ResolveResponsePayload(req apimodel.ResolveRequest) (
	ResolveResponsePayload, error,
) {
	for _, tr := range req.TrustAnchor {
		entityConfig, err := GetEntityConfiguration(tr)
		if err != nil {
			internal.Logf("MetadataResolver: error while obtaining entity configuration: %v", err)
			continue
		}
		var resolveEndpoint string
		if entityConfig != nil && entityConfig.Metadata != nil && entityConfig.Metadata.FederationEntity != nil {
			resolveEndpoint = entityConfig.Metadata.FederationEntity.FederationResolveEndpoint
		}
		if resolveEndpoint == "" {
			continue
		}
		remoteResolver := SimpleRemoteMetadataResolver{
			ResolveEndpoint: resolveEndpoint,
		}
		res, err := remoteResolver.ResolveResponsePayload(req)
		if err != nil {
			internal.Logf("MetadataResolver: error while obtaining resolve response: %v", err)
			continue
		}
		return res, nil
	}
	return LocalMetadataResolver{}.ResolveResponsePayload(req)
}

// ResolvePossible implements the MetadataResolver interface
func (SmartRemoteMetadataResolver) ResolvePossible(req apimodel.ResolveRequest) (bool, bool) {
	for _, tr := range req.TrustAnchor {
		entityConfig, err := GetEntityConfiguration(tr)
		if err != nil {
			internal.Logf("MetadataResolver: error while obtaining entity configuration: %v", err)
			continue
		}
		var resolveEndpoint string
		if entityConfig != nil && entityConfig.Metadata != nil && entityConfig.Metadata.FederationEntity != nil {
			resolveEndpoint = entityConfig.Metadata.FederationEntity.FederationResolveEndpoint
		}
		if resolveEndpoint == "" {
			continue
		}
		remoteResolver := SimpleRemoteMetadataResolver{
			ResolveEndpoint: resolveEndpoint,
		}
		validConfirmed, invalidConfirmed := remoteResolver.ResolvePossible(req)
		if validConfirmed {
			return true, false
		}
		if invalidConfirmed {
			return false, true
		}
	}
	return LocalMetadataResolver{}.ResolvePossible(req)
}
