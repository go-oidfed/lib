package oidfed

import (
	"slices"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/cache"
	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/internal/utils"
	"github.com/go-oidfed/lib/unixtime"
)

// EntityObserver is a callback interface that PeriodicEntityCollector
// can call for each discovered entity, e.g. to trigger proactive resolve generation.
type EntityObserver interface {
	// OnDiscoveredEntities is called with the trust anchor and the full set of
	// entities discovered for it.
	OnDiscoveredEntities(trustAnchor string, entities []*CollectedEntity)
}

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

	SortEntitiesComparisonFunc func(a, b *CollectedEntity) int
	PagingLimit                int `yaml:"paging_limit"`

	// internal state
	cacheMutex sync.RWMutex
	startOnce  sync.Once
	stopOnce   sync.Once
	stopCh     chan struct{}

	// Optional handler invoked after each trust anchor collection with the
	// discovered entities; can be used to trigger proactive resolver jobs.
	Handler EntityObserver
}

type cachedCollection struct {
	Entities    []*CollectedEntity
	LastUpdated unixtime.Unixtime
}

// defaultInterval is used if no interval is configured.
const defaultInterval = time.Hour * 8

// periodicCacheSubsystem defines the cache subsystem key for this collector.
const (
	periodicCacheSubsystem    = "periodic_entity_collection"
	cacheSubSubSystemAll      = "all"
	cacheSubSubSystemRequests = "requests"
)

// Start launches the periodic background collection. Calling Start multiple
// times is safe; only the first call has an effect.
func (p *PeriodicEntityCollector) Start() {
	p.startOnce.Do(
		func() {
			if p.Collector == nil {
				p.Collector = &SimpleEntityCollector{}
			}
			p.stopCh = make(chan struct{})

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
func (p *PeriodicEntityCollector) CollectEntities(req apimodel.EntityCollectionRequest) (
	*EntityCollectionResponse, *ErrorResponse,
) {
	p.Start()
	if p.PagingLimit < req.Limit || req.Limit <= 0 {
		req.Limit = p.PagingLimit
	}
	reqHash, err := utils.HashStruct(req)
	if err != nil {
		return nil, &ErrorResponse{
			Status: fiber.StatusInternalServerError,
			Error:  ErrorServerError(errors.Wrap(err, "PeriodicEntityCollector: error while hashing request").Error()),
		}
	}
	cacheRequestKey := cache.Key(periodicCacheSubsystem, cacheSubSubSystemRequests, reqHash)
	var res EntityCollectionResponse
	p.cacheMutex.RLock()
	set, err := cache.Get(cacheRequestKey, &res)
	p.cacheMutex.RUnlock()
	if err != nil {
		return nil, &ErrorResponse{
			Status: fiber.StatusInternalServerError,
			Error: ErrorServerError(
				errors.Wrap(
					err, "PeriodicEntityCollector: error while retrieving cached response",
				).Error(),
			),
		}
	}
	if set {
		return &res, nil
	}

	var cc cachedCollection
	p.cacheMutex.RLock()
	set, err = cache.Get(cache.Key(periodicCacheSubsystem, cacheSubSubSystemAll, req.TrustAnchor), &cc)
	p.cacheMutex.RUnlock()
	if err != nil {
		return nil, &ErrorResponse{
			Status: fiber.StatusInternalServerError,
			Error: ErrorServerError(
				errors.Wrap(
					err, "PeriodicEntityCollector: error while retrieving cached collection",
				).Error(),
			),
		}
	}
	if !set {
		return nil, &ErrorResponse{
			Error:  ErrorInvalidTrustAnchor("trust anchor not supported"),
			Status: fiber.StatusNotFound,
		}
	}
	entities := FilterAndTrimEntities(cc.Entities, req)
	if req.FromEntityID != "" {
		n, found := slices.BinarySearchFunc(
			entities, &CollectedEntity{EntityID: req.FromEntityID}, p.SortEntitiesComparisonFunc,
		)
		if !found {
			return nil, &ErrorResponse{
				Error:  &Error{Error: EntityIDNotFound},
				Status: fiber.StatusNotFound,
			}
		}
		entities = entities[n:]
	}
	var nextEntityID string
	if len(entities) > req.Limit {
		others := entities[req.Limit:]
		entities = entities[:req.Limit]
		nextEntityID = others[0].EntityID
		go preparePaginatedResponses(req, others, &cc.LastUpdated, p.Interval)
	}
	res = EntityCollectionResponse{
		FederationEntities: entities,
		LastUpdated:        &cc.LastUpdated,
		NextEntityID:       nextEntityID,
	}
	if err = cache.Set(cacheRequestKey, res, p.Interval); err != nil {
		internal.Errorf("PeriodicEntityCollector cache set error: %v", err)
	}
	return &res, nil
}

func preparePaginatedResponses(
	req apimodel.EntityCollectionRequest, entities []*CollectedEntity,
	lastUpdated *unixtime.Unixtime, interval time.Duration,
) {
	for len(entities) > 0 {
		var others []*CollectedEntity
		if len(entities) > req.Limit {
			others = entities[req.Limit:]
			entities = entities[:req.Limit]
		}
		var nextEntityID string
		if len(others) > 0 {
			nextEntityID = others[0].EntityID
		}
		res := EntityCollectionResponse{
			FederationEntities: entities,
			LastUpdated:        lastUpdated,
			NextEntityID:       nextEntityID,
		}
		req.FromEntityID = entities[0].EntityID
		reqHash, err := utils.HashStruct(req)
		if err != nil {
			internal.WithError(err).Error("PeriodicEntityCollector: error while hashing request")
		}
		cacheRequestKey := cache.Key(periodicCacheSubsystem, cacheSubSubSystemRequests, reqHash)
		if err = cache.Set(cacheRequestKey, res, interval); err != nil {
			internal.Errorf("PeriodicEntityCollector cache set error: %v", err)
		}
		entities = others
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
	p.cacheMutex.Lock()
	defer p.cacheMutex.Unlock()

	if err := cache.Clear(periodicCacheSubsystem); err != nil {
		internal.Errorf("PeriodicEntityCollector cache clear error: %v", err)
	}

	// Worker pool pattern with a buffered semaphore channel.
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
			res, _ := p.Collector.CollectEntities(req)
			if res == nil {
				return
			}
			if p.SortEntitiesComparisonFunc != nil {
				slices.SortFunc(res.FederationEntities, p.SortEntitiesComparisonFunc)
			}
			if err := cache.Set(
				cache.Key(periodicCacheSubsystem, cacheSubSubSystemAll, trustAnchor),
				cachedCollection{
					Entities:    res.FederationEntities,
					LastUpdated: unixtime.Now(),
				},
				p.Interval,
			); err != nil {
				internal.Errorf("PeriodicEntityCollector cache set error: %v", err)
			}

			// Notify handler for proactive resolve generation.
			if p.Handler != nil && len(res.FederationEntities) > 0 {
				p.Handler.OnDiscoveredEntities(trustAnchor, res.FederationEntities)
			}
		}(ta)
	}
	wg.Wait()
}
