package oidfed

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-oidfed/lib/apimodel"
)

type mockPeriodicCollector struct {
	entities []*CollectedEntity
	calls    atomic.Int32
}

func (m *mockPeriodicCollector) CollectEntities(req apimodel.EntityCollectionRequest) (
	*EntityCollectionResponse, *ErrorResponse,
) {
	m.calls.Add(1)
	return &EntityCollectionResponse{Entities: m.entities}, nil
}

func testPeriodicCollector(ta string, collector EntityCollector) *PeriodicEntityCollector {
	return &PeriodicEntityCollector{
		Collector:    collector,
		TrustAnchors: []string{ta},
		Interval:     time.Hour,
		Concurrency:  2,
	}
}

func TestPeriodicEntityCollectorNoLimitReturnsAll(t *testing.T) {
	const ta = "https://ta1.example"
	mock := &mockPeriodicCollector{
		entities: []*CollectedEntity{
			{EntityID: "https://op1.example"},
			{EntityID: "https://op2.example"},
			{EntityID: "https://op3.example"},
		},
	}
	p := testPeriodicCollector(ta, mock)
	t.Cleanup(p.Stop)

	// Populate the cache synchronously, then serve from it.
	p.runOnce()
	res, errRes := p.CollectEntities(apimodel.EntityCollectionRequest{
		TrustAnchor: ta,
	})
	if errRes != nil {
		t.Fatalf("unexpected error response: %+v", errRes)
	}
	if len(res.Entities) != 3 {
		t.Fatalf("expected 3 entities, got %d", len(res.Entities))
	}
	if res.Next != "" {
		t.Fatalf("expected no next page when no limit is set, got %q", res.Next)
	}
}

func TestPeriodicEntityCollectorServesCachedCollection(t *testing.T) {
	const ta = "https://ta2.example"
	mock := &mockPeriodicCollector{
		entities: []*CollectedEntity{{EntityID: "https://op1.example"}},
	}
	p := testPeriodicCollector(ta, mock)
	t.Cleanup(p.Stop)

	req := apimodel.EntityCollectionRequest{TrustAnchor: ta}
	// The background refresh populates the cache asynchronously; wait for it.
	deadline := time.Now().Add(3 * time.Second)
	for {
		res, errRes := p.CollectEntities(req)
		if errRes == nil && len(res.Entities) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cache did not warm up: %+v", errRes)
		}
		time.Sleep(10 * time.Millisecond)
	}
	warmedCalls := mock.calls.Load()

	// Once warm, repeated requests are served from the cache and do not invoke
	// the collector again.
	for i := 0; i < 3; i++ {
		res, errRes := p.CollectEntities(req)
		if errRes != nil {
			t.Fatalf("expected cached response, got error %+v", errRes)
		}
		if len(res.Entities) != 1 {
			t.Fatalf("expected 1 entity, got %d", len(res.Entities))
		}
	}
	if got := mock.calls.Load(); got != warmedCalls {
		t.Fatalf("collector was invoked again after warm-up: %d -> %d", warmedCalls, got)
	}
}

func TestPeriodicEntityCollectorKeepsOldDataOnFailedRefresh(t *testing.T) {
	const ta = "https://ta3.example"
	mock := &mockPeriodicCollector{
		entities: []*CollectedEntity{{EntityID: "https://op1.example"}},
	}
	p := testPeriodicCollector(ta, mock)
	t.Cleanup(p.Stop)

	p.runOnce()

	// A failed refresh must not drop the previously collected data.
	p.Collector = &failingPeriodicCollector{}
	p.runOnce()

	res, errRes := p.CollectEntities(apimodel.EntityCollectionRequest{
		TrustAnchor: ta,
	})
	if errRes != nil {
		t.Fatalf("expected old data to be served after a failed refresh, got %+v", errRes)
	}
	if len(res.Entities) != 1 || res.Entities[0].EntityID != "https://op1.example" {
		t.Fatalf("expected old entity to remain, got %+v", res.Entities)
	}
}

type failingPeriodicCollector struct{}

func (*failingPeriodicCollector) CollectEntities(req apimodel.EntityCollectionRequest) (
	*EntityCollectionResponse, *ErrorResponse,
) {
	return nil, nil
}

// blockingPeriodicCollector blocks until released and returns the given entities.
type blockingPeriodicCollector struct {
	release  chan struct{}
	entities []*CollectedEntity
}

func (b *blockingPeriodicCollector) CollectEntities(req apimodel.EntityCollectionRequest) (
	*EntityCollectionResponse, *ErrorResponse,
) {
	<-b.release
	return &EntityCollectionResponse{Entities: b.entities}, nil
}

func TestPeriodicEntityCollectorReadersDoNotBlockOnRefresh(t *testing.T) {
	const ta = "https://ta4.example"
	blocker := &blockingPeriodicCollector{
		release:  make(chan struct{}),
		entities: []*CollectedEntity{{EntityID: "https://op1.example"}},
	}
	p := testPeriodicCollector(ta, blocker)
	t.Cleanup(p.Stop)

	// Warm the cache first so there is something to serve.
	p.Collector = &mockPeriodicCollector{entities: []*CollectedEntity{{EntityID: "https://op0.example"}}}
	p.runOnce()

	// Start a refresh that blocks in the collector.
	p.Collector = blocker
	done := make(chan struct{})
	go func() {
		p.runOnce()
		close(done)
	}()

	// A read during the blocked refresh must return immediately from the cache.
	start := time.Now()
	res, errRes := p.CollectEntities(apimodel.EntityCollectionRequest{
		TrustAnchor: ta,
	})
	elapsed := time.Since(start)
	if errRes != nil {
		t.Fatalf("unexpected error during refresh: %+v", errRes)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("CollectEntities blocked during refresh for %s", elapsed)
	}
	if len(res.Entities) != 1 {
		t.Fatalf("expected cached entity, got %d", len(res.Entities))
	}

	close(blocker.release)
	<-done
}
