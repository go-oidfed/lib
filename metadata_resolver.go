package oidfed

import (
	"encoding/json"

	"github.com/go-resty/resty/v2"
	"github.com/google/go-querystring/query"
	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/internal/http"
	internalhttp "github.com/go-oidfed/lib/internal/http"
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
		TrustAnchors:         NewTrustAnchorsFromEntityIDs(req.TrustAnchor...),
		StartingEntity:       req.Subject,
		Types:                req.EntityTypes,
		TrustAnchorHintsMode: TrustAnchorHintsModePrefer,
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
		TrustAnchors:         NewTrustAnchorsFromEntityIDs(req.TrustAnchor...),
		StartingEntity:       req.Subject,
		Types:                req.EntityTypes,
		TrustAnchorHintsMode: TrustAnchorHintsModeIgnore,
	}
	chains := tr.ResolveToValidChains()
	valid := len(chains) > 0
	return valid, !valid
}

// SimpleRemoteMetadataResolver is a MetadataResolver that utilizes a given
// ResolveEndpoint
type SimpleRemoteMetadataResolver struct {
	ResolveEndpoint string
	// ClientAuth, when non-nil, authenticates every resolve request with a
	// private_key_jwt client assertion (audience = ResolveEndpoint) sent as a
	// form-encoded POST containing the resolve params plus
	// client_assertion_type/client_assertion. When nil, an unauthenticated GET
	// with the params as URL query is used. EC-based advertisement checks
	// (federation_resolve_endpoint_auth_methods) are the caller's concern —
	// see SmartRemoteMetadataResolver.
	ClientAuth *RequestObjectProducer
	// Headers, when non-nil, are added to every request.
	Headers map[string]string
	// AlgsFromEC, when non-nil, reads the endpoint's acceptable signing
	// algorithms from the target entity's Entity Configuration. If nil, the
	// producer's DefaultSigner is used.
	AlgsFromEC func() []string
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

	// process converts the raw HTTP result (via the shared resty.Response and
	// *http.HttpError result shape) into a resolveStatus. It is shared by the
	// authenticated POST and the unauthenticated GET paths.
	process := func(res *resty.Response, errRes *internalhttp.HttpError, err error) (*ResolveResponse, int, error) {
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

	if r.ClientAuth != nil {
		algs := []string(nil)
		if r.AlgsFromEC != nil {
			algs = r.AlgsFromEC()
		}
		form, err := clientAuthForm(params, r.ClientAuth, r.ResolveEndpoint, algs)
		if err != nil {
			return nil, resolveStatus, errors.WithStack(err)
		}
		authReq := internalhttp.Do().R().SetFormDataFromValues(form).SetError(&internalhttp.HttpError{})
		for k, v := range r.Headers {
			authReq.SetHeader(k, v)
		}
		res, re := authReq.Post(r.ResolveEndpoint)
		if re != nil {
			return process(res, nil, errors.WithStack(re))
		}
		var errRes *internalhttp.HttpError
		if e, ok := res.Error().(*internalhttp.HttpError); ok && e != nil && e.Error != "" {
			e.Status = res.RawResponse.StatusCode
			errRes = e
		}
		return process(res, errRes, nil)
	}

	res, errRes, err := http.Get(r.ResolveEndpoint, params, nil)
	return process(res, errRes, err)
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

// RemoteResolverClientAuth configures private_key_jwt client authentication
// for a SmartRemoteMetadataResolver.
type RemoteResolverClientAuth struct {
	// ROProducer produces the client assertion JWT (private_key_jwt).
	ROProducer *RequestObjectProducer
	// Force, when true, authenticates against every trust anchor's resolve
	// endpoint even when its EC does not advertise private_key_jwt; when
	// false, endpoints are authenticated exactly when the EC advertises it.
	Force bool
}

// SmartRemoteMetadataResolver is a MetadataResolver that utilizes remote
// resolve endpoints. It will iterate through the resolve endpoints of the
// given TrustAnchors and stop if one is successful,
// if no resolve endpoint is successful, local resolving is used
type SmartRemoteMetadataResolver struct {
	// ClientAuth, when non-nil, enables private_key_jwt client authentication
	// against each trust anchor's resolve endpoint. With Force=false, a
	// resolve endpoint is authenticated exactly when the trust anchor's EC
	// advertises private_key_jwt in
	// federation_resolve_endpoint_auth_methods; with Force=true, every resolve
	// request is authenticated.
	ClientAuth *RemoteResolverClientAuth
}

// remoteResolverForTA builds a SimpleRemoteMetadataResolver for a trust
// anchor's resolve endpoint, applying this resolver's ClientAuth. When
// r.ClientAuth is non-nil, the endpoint is authenticated (POST + client
// assertion) if Force is set or the trust anchor's EC advertises
// private_key_jwt; signing algorithms are read from the EC. With a nil
// ClientAuth the plain unauthenticated resolver is returned.
func (r SmartRemoteMetadataResolver) remoteResolverForTA(
	resolveEndpoint string, fe *FederationEntityMetadata,
) SimpleRemoteMetadataResolver {
	rr := SimpleRemoteMetadataResolver{
		ResolveEndpoint: resolveEndpoint,
	}
	if r.ClientAuth != nil {
		if r.ClientAuth.Force || clientAuthRequired(fe.FederationResolveEndpointAuthMethods) {
			rr.ClientAuth = r.ClientAuth.ROProducer
		}
		rr.AlgsFromEC = func() []string { return endpointAlgsFromEC(fe) }
	}
	return rr
}

// Resolve implements the MetadataResolver interface
func (r SmartRemoteMetadataResolver) Resolve(req apimodel.ResolveRequest) (*Metadata, error) {
	res, err := r.ResolveResponsePayload(req)
	if err != nil {
		return nil, err
	}
	return res.Metadata, nil
}

// ResolveResponsePayload implements the MetadataResolver interface
func (r SmartRemoteMetadataResolver) ResolveResponsePayload(req apimodel.ResolveRequest) (
	ResolveResponsePayload, error,
) {
	// Prefer trust anchors hinted by the starting entity; fall back to others.
	// Default mode: Prefer
	var ordered []string
	if req.Subject != "" {
		if starting, err := GetEntityConfiguration(req.Subject); err == nil && starting != nil {
			hints := starting.TrustAnchorHints
			if len(hints) > 0 {
				hintSet := map[string]struct{}{}
				for _, h := range hints {
					hintSet[h] = struct{}{}
				}
				// intersection first, preserving req.TrustAnchor order
				for _, id := range req.TrustAnchor {
					if _, ok := hintSet[id]; ok {
						ordered = append(ordered, id)
					}
				}
				// then the remaining anchors not in hints
				for _, id := range req.TrustAnchor {
					if _, ok := hintSet[id]; !ok {
						ordered = append(ordered, id)
					}
				}
			}
		}
	}
	if len(ordered) == 0 {
		ordered = req.TrustAnchor
	}
	for _, tr := range ordered {
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
		remoteResolver := r.remoteResolverForTA(resolveEndpoint, entityConfig.Metadata.FederationEntity)
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
func (r SmartRemoteMetadataResolver) ResolvePossible(req apimodel.ResolveRequest) (bool, bool) {
	// Prefer trust anchors hinted by the starting entity; fall back to others.
	var ordered []string
	if req.Subject != "" {
		if starting, err := GetEntityConfiguration(req.Subject); err == nil && starting != nil {
			hints := starting.TrustAnchorHints
			if len(hints) > 0 {
				hintSet := map[string]struct{}{}
				for _, h := range hints {
					hintSet[h] = struct{}{}
				}
				for _, id := range req.TrustAnchor {
					if _, ok := hintSet[id]; ok {
						ordered = append(ordered, id)
					}
				}
				for _, id := range req.TrustAnchor {
					if _, ok := hintSet[id]; !ok {
						ordered = append(ordered, id)
					}
				}
			}
		}
	}
	if len(ordered) == 0 {
		ordered = req.TrustAnchor
	}
	for _, tr := range ordered {
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
		remoteResolver := r.remoteResolverForTA(resolveEndpoint, entityConfig.Metadata.FederationEntity)
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
