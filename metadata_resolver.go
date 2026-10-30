package oidfed

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"time"

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

// Errors returned by LocalMetadataResolver when it cannot produce a resolve
// result. Callers distinguish the resolution stage with errors.Is:
//
//   - ErrNoTrustChainFound: the subject has no signature-valid path to a
//     configured trust anchor (or, since ResolveToValidChains also applies the
//     metadata filter, none of the existing paths pass metadata policy).
//   - ErrNoTrustChainWithValidMetadata: signature-valid paths exist but none
//     pass metadata policy evaluation.
var (
	ErrNoTrustChainFound             = stderrors.New("no trust chain found")
	ErrNoTrustChainWithValidMetadata = stderrors.New("no trust chain with valid metadata found")
)

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
		Ctx:                  req.Context,
	}
	chains := tr.ResolveToValidChains()
	if len(chains) == 0 {
		err = ErrNoTrustChainFound
		return
	}
	chains = chains.SortAsc(TrustChainScoringPathLen)
	for _, chain = range chains {
		m, err := chain.Metadata()
		if err == nil {
			res.TrustChain = chain.Messages()
			res.Metadata = m
			res.ValidUntil = chain.ExpiresAt()
			res.TrustAnchor = chain[len(chain)-1].Issuer
			return res, chain, nil
		}
	}
	err = ErrNoTrustChainWithValidMetadata
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
		Ctx:                  req.Context,
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
	// The caller's context bounds/cancels the request when provided. Both the
	// unauthenticated GET and the authenticated POST honor it; a canceled
	// (or timed-out) context aborts the attempt and stops Resty from
	// retrying, so a slow or dead resolve endpoint is skipped in favor of
	// the next trust anchor or the fallback resolver.
	ctx := req.Context
	if ctx == nil {
		ctx = context.Background()
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
		rres.ValidUntil = rres.ExpiresAt
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
		authReq := internalhttp.Do().R().SetContext(ctx).SetFormDataFromValues(form).SetError(&internalhttp.HttpError{})
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

	res, errRes, err := http.GetCtx(ctx, r.ResolveEndpoint, params, nil)
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

// orderedTrustAnchors returns the trust anchors in resolution order: those
// hinted by the starting entity's entity configuration first (preserving the
// order of req.TrustAnchor), then the remaining anchors.
func orderedTrustAnchors(req apimodel.ResolveRequest) []string {
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
	return ordered
}

// resolveViaTA resolves req against a single trust anchor's resolve endpoint,
// fetching the trust anchor's entity configuration first. It is the per-TA
// candidate function of the parallel smart resolver.
func (r SmartRemoteMetadataResolver) resolveViaTA(
	req apimodel.ResolveRequest, ta string,
) (ResolveResponsePayload, error) {
	entityConfig, err := GetEntityConfiguration(ta)
	if err != nil {
		internal.Logf("MetadataResolver: error while obtaining entity configuration: %v", err)
		return ResolveResponsePayload{}, err
	}
	var resolveEndpoint string
	if entityConfig != nil && entityConfig.Metadata != nil && entityConfig.Metadata.FederationEntity != nil {
		resolveEndpoint = entityConfig.Metadata.FederationEntity.FederationResolveEndpoint
	}
	if resolveEndpoint == "" {
		return ResolveResponsePayload{}, errors.New("trust anchor has no federation_resolve_endpoint")
	}
	remoteResolver := r.remoteResolverForTA(resolveEndpoint, entityConfig.Metadata.FederationEntity)
	res, err := remoteResolver.ResolveResponsePayload(req)
	if err != nil {
		internal.Logf("MetadataResolver: error while obtaining resolve response: %v", err)
	}
	return res, err
}

// resolvePossibleViaTA is the per-TA candidate function of the parallel smart
// resolver's ResolvePossible.
func (r SmartRemoteMetadataResolver) resolvePossibleViaTA(
	req apimodel.ResolveRequest, ta string,
) (valid, invalid bool) {
	entityConfig, err := GetEntityConfiguration(ta)
	if err != nil {
		internal.Logf("MetadataResolver: error while obtaining entity configuration: %v", err)
		return false, false
	}
	var resolveEndpoint string
	if entityConfig != nil && entityConfig.Metadata != nil && entityConfig.Metadata.FederationEntity != nil {
		resolveEndpoint = entityConfig.Metadata.FederationEntity.FederationResolveEndpoint
	}
	if resolveEndpoint == "" {
		return false, false
	}
	return r.remoteResolverForTA(resolveEndpoint, entityConfig.Metadata.FederationEntity).ResolvePossible(req)
}

// ResolveResponsePayload implements the MetadataResolver interface. All
// trust anchors are queried concurrently and the best result (shortest trust
// chain) wins, so one slow or unreachable trust anchor cannot delay a valid
// one; see ParallelMetadataResolver for the racing semantics.
func (r SmartRemoteMetadataResolver) ResolveResponsePayload(req apimodel.ResolveRequest) (
	ResolveResponsePayload, error,
) {
	ordered := orderedTrustAnchors(req)
	successes, _ := raceCandidates(
		req.Context, len(ordered), maxConcurrentResolverCandidates,
		func(ctx context.Context, i int) (ResolveResponsePayload, error) {
			candidateReq := req
			candidateReq.Context = ctx
			return r.resolveViaTA(candidateReq, ordered[i])
		},
		defaultParallelResolveDeadline, defaultParallelResolveGrace,
	)
	if len(successes) == 0 {
		return LocalMetadataResolver{}.ResolveResponsePayload(req)
	}
	return bestResolveResponsePayload(successes), nil
}

// ResolvePossible implements the MetadataResolver interface. Like
// ResolveResponsePayload it queries all trust anchors concurrently; a valid
// result from any anchor wins over an invalid one.
func (r SmartRemoteMetadataResolver) ResolvePossible(req apimodel.ResolveRequest) (bool, bool) {
	type possible struct{ valid, invalid bool }
	ordered := orderedTrustAnchors(req)
	successes, _ := raceCandidates(
		req.Context, len(ordered), maxConcurrentResolverCandidates,
		func(ctx context.Context, i int) (possible, error) {
			candidateReq := req
			candidateReq.Context = ctx
			valid, invalid := r.resolvePossibleViaTA(candidateReq, ordered[i])
			return possible{valid: valid, invalid: invalid}, nil
		},
		defaultParallelResolveDeadline, defaultParallelResolveGrace,
	)
	for _, res := range successes {
		if res.value.valid {
			return true, false
		}
	}
	for _, res := range successes {
		if res.value.invalid {
			return false, true
		}
	}
	return LocalMetadataResolver{}.ResolvePossible(req)
}

const (
	// defaultParallelResolveDeadline bounds the total time a parallel resolve
	// (explicit resolver list or per-trust-anchor fan-out) waits for its
	// candidates before giving up.
	defaultParallelResolveDeadline = 15 * time.Second
	// defaultParallelResolveGrace is how long a parallel resolve keeps
	// waiting after the first candidate succeeded for a slower candidate to
	// produce a better (shorter) trust chain. Results are scored by trust
	// chain length; on a tie the earliest-arrived result wins.
	defaultParallelResolveGrace = time.Second
	// maxConcurrentResolverCandidates caps how many candidate resolvers run
	// at once; further candidates queue until a slot frees up or the
	// deadline expires.
	maxConcurrentResolverCandidates = 8
)

// ParallelMetadataResolver is a MetadataResolver that races multiple
// candidate resolvers concurrently, so that one slow or unresponsive
// candidate cannot delay a fast valid one. Candidates run concurrently
// (capped at maxConcurrentResolverCandidates). The resolve finishes when
// either all candidates completed, the grace period after the first success
// elapsed, or the deadline expires — whichever comes first — and returns the
// best result received so far: the one with the shortest trust chain, with
// the earliest arrival winning ties. If no candidate succeeds, the last
// error is returned.
type ParallelMetadataResolver struct {
	Resolvers []MetadataResolver
	// Deadline bounds the total resolve duration. Zero means
	// defaultParallelResolveDeadline.
	Deadline time.Duration
	// GracePeriod is how long the resolve keeps waiting after the first
	// candidate succeeded for a better result. Zero means
	// defaultParallelResolveGrace.
	GracePeriod time.Duration
}

// Resolve implements the MetadataResolver interface.
func (r ParallelMetadataResolver) Resolve(req apimodel.ResolveRequest) (*Metadata, error) {
	res, err := r.ResolveResponsePayload(req)
	if err != nil {
		return nil, err
	}
	return res.Metadata, nil
}

// ResolveResponsePayload implements the MetadataResolver interface.
func (r ParallelMetadataResolver) ResolveResponsePayload(req apimodel.ResolveRequest) (
	ResolveResponsePayload, error,
) {
	results, lastErr := raceCandidates(
		req.Context, len(r.Resolvers), maxConcurrentResolverCandidates,
		func(ctx context.Context, i int) (ResolveResponsePayload, error) {
			candidateReq := req
			candidateReq.Context = ctx
			return r.Resolvers[i].ResolveResponsePayload(candidateReq)
		},
		r.Deadline, r.GracePeriod,
	)
	if len(results) == 0 {
		return ResolveResponsePayload{}, lastErr
	}
	return bestResolveResponsePayload(results), nil
}

// ResolvePossible implements the MetadataResolver interface. Like
// ResolveResponsePayload it races all resolvers; a valid result from any
// resolver wins over an invalid one.
func (r ParallelMetadataResolver) ResolvePossible(req apimodel.ResolveRequest) (bool, bool) {
	type possible struct{ valid, invalid bool }
	results, _ := raceCandidates(
		req.Context, len(r.Resolvers), maxConcurrentResolverCandidates,
		func(ctx context.Context, i int) (possible, error) {
			candidateReq := req
			candidateReq.Context = ctx
			valid, invalid := r.Resolvers[i].ResolvePossible(candidateReq)
			return possible{valid: valid, invalid: invalid}, nil
		},
		r.Deadline, r.GracePeriod,
	)
	for _, res := range results {
		if res.value.valid {
			return true, false
		}
	}
	for _, res := range results {
		if res.value.invalid {
			return false, true
		}
	}
	return false, false
}

// candidateResult is the outcome of one candidate in a raced resolve.
type candidateResult[T any] struct {
	value T
	err   error
}

// raceCandidates runs fetch concurrently for candidate indices 0..n-1 (at
// most maxConcurrent at once) and returns all successful results in arrival
// order. Collection ends when all candidates finished, when the grace period
// after the first success elapsed, or when the deadline expired — whichever
// comes first. When the race stops early (grace/deadline) the remaining
// candidates are canceled: the parent context (the caller's, pass nil for
// none) is wrapped so a stop cancels every in-flight candidate's context,
// aborting their requests immediately instead of letting them run out their
// own (15s) request timeouts. When no candidate succeeds, the last error is
// returned.
func raceCandidates[T any](
	parent context.Context,
	n, maxConcurrent int,
	fetch func(ctx context.Context, i int) (T, error),
	deadline, grace time.Duration,
) (successes []candidateResult[T], lastErr error) {
	if n == 0 {
		return nil, errors.New("no candidates")
	}
	if deadline <= 0 {
		deadline = defaultParallelResolveDeadline
	}
	if grace <= 0 {
		grace = defaultParallelResolveGrace
	}
	if parent == nil {
		parent = context.Background()
	}
	// The deadline is imposed on the per-candidate contexts themselves, so
	// when it fires the in-flight requests are aborted at the same moment
	// the race gives up (see the deadlineC case below).
	ctx, deadlineCancel := context.WithTimeout(parent, deadline)
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		deadlineCancel()
	}()

	results := make(chan candidateResult[T], n)
	sem := make(chan struct{}, maxConcurrent)
	for i := range n {
		go func(i int) {
			sem <- struct{}{}
			defer func() { <-sem }()
			value, err := fetch(ctx, i)
			results <- candidateResult[T]{value: value, err: err}
		}(i)
	}
	// The grace timer is only started by the first success while other
	// candidates are still in flight.
	var (
		graceTimer *time.Timer
		graceC     <-chan time.Time
	)
	defer func() {
		if graceTimer != nil {
			graceTimer.Stop()
		}
	}()
	active := n
	deadlineC := ctx.Done()
	for active > 0 {
		select {
		case res := <-results:
			active--
			if res.err != nil {
				lastErr = res.err
				continue
			}
			successes = append(successes, res)
			if graceC == nil && active > 0 {
				graceTimer = time.NewTimer(grace)
				graceC = graceTimer.C
			}
		case <-graceC:
			// Best-so-far is committed; the deferred cancel() aborts the
			// remaining in-flight branches on return.
			active = 0
		case <-deadlineC:
			// The deadline expired; the WithTimeout above already canceled
			// the per-candidate contexts.
			active = 0
		}
	}
	if len(successes) == 0 {
		if lastErr == nil {
			lastErr = errors.New("no candidate succeeded")
		}
		return nil, lastErr
	}
	return successes, nil
}

// bestResolveResponsePayload returns the result with the shortest trust chain
// (fewest statements); on ties the earliest-arrived result wins.
func bestResolveResponsePayload(results []candidateResult[ResolveResponsePayload]) ResolveResponsePayload {
	best := results[0]
	for _, res := range results[1:] {
		if len(res.value.TrustChain) < len(best.value.TrustChain) {
			best = res
		}
	}
	return best.value
}
