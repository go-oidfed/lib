package oidfed

import (
	"sync"
	"time"

	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/unixtime"
)

// PeriodicEntityCollector runs background entity collection for a set of
// trust anchors at a configurable interval. It implements EntityCollector by
// delegating synchronous collection to an inner Collector while warming caches
// in the background.
type PeriodicEntityCollector struct {
	// Collector used for actual collection (defaults to SimpleEntityCollector).
	Collector EntityCollector

	// TrustAnchors is the full list of trust anchors to iterate over.
	TrustAnchors []string

	// Interval between background collection rounds.
	Interval time.Duration `yaml:"interval"`

	// Concurrency limits simultaneous trust anchor collections per run.
	// If 0 or negative, a sensible default is used.
	Concurrency int `yaml:"concurrency"`

	// internal state
	startOnce sync.Once
	stopOnce  sync.Once
	stopCh    chan struct{}

	cacheMu sync.RWMutex
	cache   map[string]cachedCollection
}

type cachedCollection struct {
	Entities    []*CollectedEntity
	LastUpdated unixtime.Unixtime
}

// defaultInterval is used if no interval is configured.
const defaultInterval = time.Hour * 8

// Start launches the periodic background collection. Calling Start multiple
// times is safe; only the first call has an effect.
func (p *PeriodicEntityCollector) Start() {
	p.startOnce.Do(
		func() {
			if p.Collector == nil {
				p.Collector = &SimpleEntityCollector{}
			}
			p.stopCh = make(chan struct{})
			if p.cache == nil {
				p.cache = make(map[string]cachedCollection)
			}

			interval := p.Interval
			if interval <= 0 {
				interval = defaultInterval
			}

			// Run an initial round immediately to warm caches, then tick.
			go p.runOnce()

			ticker := time.NewTicker(interval)
			go func() {
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						p.runOnce()
					case <-p.stopCh:
						return
					}
				}
			}()
		},
	)
}

// Stop stops the background collection loop. It is safe to call multiple times.
func (p *PeriodicEntityCollector) Stop() {
	p.stopOnce.Do(
		func() {
			if p.stopCh != nil {
				close(p.stopCh)
			}
		},
	)
}

// CollectEntities serves from the cached periodic results, applying filters
// and trimming based on the request.
func (p *PeriodicEntityCollector) CollectEntities(req apimodel.EntityCollectionRequest) *EntityCollectionResponse {
	p.Start()
	p.cacheMu.RLock()
	cc := p.cache[req.TrustAnchor]
	p.cacheMu.RUnlock()
	if len(cc.Entities) == 0 {
		return nil
	}
	return &EntityCollectionResponse{
		FederationEntities: FilterAndTrimEntities(cc.Entities, req),
		LastUpdated:        &cc.LastUpdated,
	}
}

func (p *PeriodicEntityCollector) runOnce() {
	anchors := p.TrustAnchors
	if len(anchors) == 0 {
		return
	}

	// Determine effective concurrency.
	conc := p.Concurrency
	if conc <= 0 {
		conc = 8
	}
	if conc > len(anchors) {
		conc = len(anchors)
	}

	// Worker pool pattern with buffered semaphore channel.
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for _, ta := range anchors {
		sem <- struct{}{}
		wg.Add(1)
		go func(trustAnchor string) {
			defer wg.Done()
			defer func() { <-sem }()
			// Use a minimal request focused on warming caches.
			req := apimodel.EntityCollectionRequest{
				TrustAnchor: trustAnchor,
				EntityClaims: []string{
					"entity_types",
					"trust_marks",
				},
			}
			internal.Logf("PeriodicEntityCollector: collecting for trust anchor %s", trustAnchor)
			res := p.Collector.CollectEntities(req)
			if res == nil {
				return
			}
			p.cacheMu.Lock()
			p.cache[trustAnchor] = cachedCollection{
				Entities:    res.FederationEntities,
				LastUpdated: unixtime.Now(),
			}
			p.cacheMu.Unlock()
		}(ta)
	}
	wg.Wait()
}
