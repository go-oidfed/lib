package oidfed

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/unixtime"
)

// stubResolver is a MetadataResolver with controllable result, latency and
// error, for testing parallel resolution.
type stubResolver struct {
	metadata *Metadata
	chainLen int
	delay    time.Duration
	err      error
}

func (s stubResolver) payload() ResolveResponsePayload {
	return ResolveResponsePayload{
		Metadata:   s.metadata,
		TrustChain: make(JWSMessages, s.chainLen),
		ValidUntil: unixtime.Unixtime{Time: time.Now().Add(time.Hour)},
	}
}

func (s stubResolver) Resolve(_ apimodel.ResolveRequest) (*Metadata, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.metadata, nil
}

func (s stubResolver) ResolveResponsePayload(_ apimodel.ResolveRequest) (ResolveResponsePayload, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	if s.err != nil {
		return ResolveResponsePayload{}, s.err
	}
	return s.payload(), nil
}

func (s stubResolver) ResolvePossible(_ apimodel.ResolveRequest) (bool, bool) {
	if s.err != nil {
		return false, false
	}
	return s.metadata != nil, false
}

// ctxAwareBlockingResolver blocks on the request context and records whether
// it observed cancellation, for verifying that a race canceled its in-flight
// candidate.
type ctxAwareBlockingResolver struct {
	canceled *atomic.Bool
}

func (r ctxAwareBlockingResolver) ResolveResponsePayload(req apimodel.ResolveRequest) (ResolveResponsePayload, error) {
	if req.Context == nil {
		<-time.After(30 * time.Second)
		return ResolveResponsePayload{}, errors.New("no context")
	}
	<-req.Context.Done()
	r.canceled.Store(true)
	return ResolveResponsePayload{}, req.Context.Err()
}

func (r ctxAwareBlockingResolver) Resolve(req apimodel.ResolveRequest) (*Metadata, error) {
	res, err := r.ResolveResponsePayload(req)
	if err != nil {
		return nil, err
	}
	return res.Metadata, nil
}

func (r ctxAwareBlockingResolver) ResolvePossible(_ apimodel.ResolveRequest) (bool, bool) {
	return false, false
}

func op(issuer string) *Metadata {
	return &Metadata{OpenIDProvider: &OpenIDProviderMetadata{Issuer: issuer}}
}

// The slower candidate returns the shorter (better) trust chain within the
// grace period, so it must win over the fast candidate.
func TestParallelMetadataResolver_SlowerBetterChainWins(t *testing.T) {
	r := ParallelMetadataResolver{
		Resolvers: []MetadataResolver{
			stubResolver{metadata: op("fast"), chainLen: 4, delay: 10 * time.Millisecond},
			stubResolver{metadata: op("slow-but-better"), chainLen: 2, delay: 300 * time.Millisecond},
		},
		GracePeriod: time.Second,
		Deadline:    3 * time.Second,
	}
	start := time.Now()
	res, err := r.ResolveResponsePayload(apimodel.ResolveRequest{})
	require.NoError(t, err)
	require.NotNil(t, res.Metadata)
	assert.Equal(t, "slow-but-better", res.Metadata.OpenIDProvider.Issuer)
	// Once all candidates have completed the resolve must not wait out the
	// remaining grace period.
	assert.True(t, time.Since(start) < time.Second)
}

// A candidate that only succeeds after the grace period expired must not win.
func TestParallelMetadataResolver_GraceExpiredKeepsBestSoFar(t *testing.T) {
	r := ParallelMetadataResolver{
		Resolvers: []MetadataResolver{
			stubResolver{metadata: op("first"), chainLen: 3, delay: 10 * time.Millisecond},
			stubResolver{metadata: op("would-be-better"), chainLen: 2, delay: 400 * time.Millisecond},
		},
		GracePeriod: 100 * time.Millisecond,
		Deadline:    2 * time.Second,
	}
	res, err := r.ResolveResponsePayload(apimodel.ResolveRequest{})
	require.NoError(t, err)
	require.NotNil(t, res.Metadata)
	assert.Equal(t, "first", res.Metadata.OpenIDProvider.Issuer)
}

// A slow failing candidate must not delay a fast valid one.
func TestParallelMetadataResolver_SlowFailureDoesNotBlockValidPath(t *testing.T) {
	r := ParallelMetadataResolver{
		Resolvers: []MetadataResolver{
			stubResolver{err: errors.New("timeout"), delay: 5 * time.Second},
			stubResolver{metadata: op("valid"), chainLen: 3, delay: 20 * time.Millisecond},
		},
		GracePeriod: 200 * time.Millisecond,
		Deadline:    6 * time.Second,
	}
	start := time.Now()
	res, err := r.ResolveResponsePayload(apimodel.ResolveRequest{})
	require.NoError(t, err)
	require.NotNil(t, res.Metadata)
	assert.Equal(t, "valid", res.Metadata.OpenIDProvider.Issuer)
	assert.True(t, time.Since(start) < 3*time.Second)
}

// The deadline must bound the total resolve time even if every candidate is
// slow.
func TestParallelMetadataResolver_DeadlineBoundsTotalTime(t *testing.T) {
	r := ParallelMetadataResolver{
		Resolvers: []MetadataResolver{
			stubResolver{err: errors.New("slow"), delay: 2 * time.Second},
			stubResolver{err: errors.New("slower"), delay: 3 * time.Second},
		},
		GracePeriod: time.Millisecond,
		Deadline:    300 * time.Millisecond,
	}
	start := time.Now()
	_, err := r.ResolveResponsePayload(apimodel.ResolveRequest{})
	require.Error(t, err)
	assert.True(t, time.Since(start) < time.Second, "deadline must bound the total resolve time")
}

// Equal chain lengths keep the earliest-arrived result.
func TestParallelMetadataResolver_TieKeepsEarliest(t *testing.T) {
	r := ParallelMetadataResolver{
		Resolvers: []MetadataResolver{
			stubResolver{metadata: op("early"), chainLen: 3, delay: 10 * time.Millisecond},
			stubResolver{metadata: op("late"), chainLen: 3, delay: 200 * time.Millisecond},
		},
		GracePeriod: time.Second,
		Deadline:    2 * time.Second,
	}
	res, err := r.ResolveResponsePayload(apimodel.ResolveRequest{})
	require.NoError(t, err)
	require.NotNil(t, res.Metadata)
	assert.Equal(t, "early", res.Metadata.OpenIDProvider.Issuer)
}

// With a single candidate there is nothing to wait for after it returns,
// even if the grace period is long.
func TestParallelMetadataResolver_SingleCandidateReturnsImmediately(t *testing.T) {
	r := ParallelMetadataResolver{
		Resolvers: []MetadataResolver{
			stubResolver{metadata: op("only"), chainLen: 3, delay: 50 * time.Millisecond},
		},
		GracePeriod: time.Second,
		Deadline:    2 * time.Second,
	}
	start := time.Now()
	res, err := r.ResolveResponsePayload(apimodel.ResolveRequest{})
	require.NoError(t, err)
	require.NotNil(t, res.Metadata)
	assert.Equal(t, "only", res.Metadata.OpenIDProvider.Issuer)
	assert.True(t, time.Since(start) < 500*time.Millisecond)
}

// The selected result must carry the winner's ValidUntil so downstream
// caching can bound the lifetime.
func TestParallelMetadataResolver_KeepsWinnerLifetime(t *testing.T) {
	r := ParallelMetadataResolver{
		Resolvers: []MetadataResolver{
			stubResolver{metadata: op("winner"), chainLen: 2, delay: 10 * time.Millisecond},
			stubResolver{metadata: op("longer"), chainLen: 5, delay: 10 * time.Millisecond},
		},
		GracePeriod: 100 * time.Millisecond,
		Deadline:    time.Second,
	}
	res, err := r.ResolveResponsePayload(apimodel.ResolveRequest{})
	require.NoError(t, err)
	assert.Equal(t, "winner", res.Metadata.OpenIDProvider.Issuer)
	assert.False(t, res.ValidUntil.IsZero())
}

// TestParallelMetadataResolver_GraceCancelsInFlight verifies that when the
// grace period after the first success expires, the still-running candidates
// are canceled (their request contexts done) instead of being left to run
// out their own request timeouts.
func TestParallelMetadataResolver_GraceCancelsInFlight(t *testing.T) {
	var canceled atomic.Bool
	r := ParallelMetadataResolver{
		Resolvers: []MetadataResolver{
			stubResolver{metadata: op("fast"), chainLen: 3, delay: 10 * time.Millisecond},
			ctxAwareBlockingResolver{canceled: &canceled},
		},
		GracePeriod: 50 * time.Millisecond,
		Deadline:    3 * time.Second,
	}
	res, err := r.ResolveResponsePayload(apimodel.ResolveRequest{})
	require.NoError(t, err)
	require.NotNil(t, res.Metadata)
	assert.Equal(t, "fast", res.Metadata.OpenIDProvider.Issuer)
	// The blocking candidate must observe cancellation shortly after the
	// grace window, far before its own (30s) timeout.
	assert.Eventually(t, canceled.Load, time.Second, 10*time.Millisecond)
}

// TestResolveResponse_CanceledContextAbortsGET verifies that a canceled
// ResolveRequest.Context aborts an unauthenticated remote resolve instead of
// waiting out the remote's response (and is not retried).
func TestResolveResponse_CanceledContextAbortsGET(t *testing.T) {
	var attempts atomic.Int32
	httpmock.RegisterResponder(http.MethodGet, testResolveURL, func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		time.Sleep(30 * time.Second)
		return httpmock.NewStringResponse(200, ""), nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // resolve must not proceed

	r := SimpleRemoteMetadataResolver{ResolveEndpoint: testResolveURL}
	start := time.Now()
	_, _, err := r.ResolveResponse(apimodel.ResolveRequest{
		Subject:     testResolveSub,
		TrustAnchor: []string{"https://ta.example"},
		Context:     ctx,
	})
	assert.Error(t, err, "a canceled context must abort the request")
	assert.Less(t, time.Since(start), 3*time.Second, "a canceled context must abort quickly, took %v", time.Since(start))
	assert.Equal(t, int32(1), attempts.Load(), "a canceled request must not be retried")
}

// TestResolveResponse_CanceledContextAbortsPost verifies the same for the
// authenticated private_key_jwt POST path.
func TestResolveResponse_CanceledContextAbortsPost(t *testing.T) {
	rop := clientAuthTestProducer(t)
	var attempts atomic.Int32
	httpmock.RegisterResponder(http.MethodPost, testResolveURL, func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		time.Sleep(30 * time.Second)
		return httpmock.NewStringResponse(200, ""), nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := SimpleRemoteMetadataResolver{
		ResolveEndpoint: testResolveURL,
		ClientAuth:      rop,
	}
	start := time.Now()
	_, _, err := r.ResolveResponse(apimodel.ResolveRequest{
		Subject:     testResolveSub,
		TrustAnchor: []string{"https://ta.example"},
		Context:     ctx,
	})
	assert.Error(t, err, "a canceled context must abort the request")
	assert.Less(t, time.Since(start), 3*time.Second, "a canceled context must abort quickly, took %v", time.Since(start))
	assert.Equal(t, int32(1), attempts.Load(), "a canceled request must not be retried")
}
