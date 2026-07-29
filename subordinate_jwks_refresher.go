package oidfed

import (
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/scylladb/go-set/strset"

	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/jwx"
)

const (
	// subPollBuffer is added to the EC-derived poll interval so the refresher
	// polls slightly before the EC expires.
	subPollBuffer = 1 * time.Second
	// subInitialBackoff is the starting backoff after a failed poll.
	subInitialBackoff = 1 * time.Second
	// subMaxBackoff caps the exponential backoff after repeated failures.
	subMaxBackoff = 5 * time.Minute
	// SubMinPollInterval is the floor for poll intervals to avoid busy-looping
	// when an EC has a very short or already-passed expiration.
	SubMinPollInterval = 1 * time.Minute
)

// SubordinateJWKSInfo is the subset of subordinate state the refresher needs.
type SubordinateJWKSInfo struct {
	EntityID         string
	EnableJWKSUpdate bool
	JWKSPollInterval *int64 // seconds; nil or <=0 means derive from EC exp
	JWKS             jwx.JWKS
}

// SubordinateJWKSRefreshStorage is the storage interface the
// SubordinateJWKSRefresher relies on. Implementations must be safe for
// concurrent use.
type SubordinateJWKSRefreshStorage interface {
	// ListEnabled returns all subordinates with EnableJWKSUpdate=true.
	ListEnabled() ([]SubordinateJWKSInfo, error)
	// Get returns the subordinate with the given entity ID, or
	// (nil, nil) if not found.
	Get(entityID string) (*SubordinateJWKSInfo, error)
	// UpdateJWKS replaces the stored JWKS for the given entity ID.
	UpdateJWKS(entityID string, jwks jwx.JWKS) error
}

// ECFetcher fetches and returns the parsed Entity Configuration for an entity.
// GetEntityConfiguration is the standard implementation.
type ECFetcher func(entityID string) (*EntityStatement, error)

// SubordinateJWKSRefresher periodically polls the Entity Configuration of
// subordinates with EnableJWKSUpdate=true and updates their stored JWKS when
// the EC's jwks changes). It is modeled on TAJWKSRefresher but
// keeps JWKS only in storage (subordinates have no in-memory JWKS copy).
type SubordinateJWKSRefresher struct {
	storage SubordinateJWKSRefreshStorage
	fetch   ECFetcher
	logger  zerolog.Logger

	mu      sync.Mutex
	state   map[string]*subPollState
	stopCh  chan struct{}
	wg      sync.WaitGroup
	started bool
}

type subPollState struct {
	lastKnownKIDs *strset.Set
	backoff       time.Duration
	mu            sync.RWMutex
	stopCh        chan struct{}
}

// SubordinateJWKSRefresherConfig configures the subordinate JWKS refresher.
type SubordinateJWKSRefresherConfig struct {
	// LogLevel sets the minimum log level. Default: "info".
	LogLevel string `yaml:"log_level"`
}

// NewSubordinateJWKSRefresher creates a new SubordinateJWKSRefresher. The
// refresher is not started; call Start.
func NewSubordinateJWKSRefresher(
	storage SubordinateJWKSRefreshStorage,
	fetch ECFetcher,
	configs ...*SubordinateJWKSRefresherConfig,
) (*SubordinateJWKSRefresher, error) {
	if storage == nil {
		return nil, errors.New("storage is required")
	}
	if fetch == nil {
		fetch = GetEntityConfiguration
	}
	logLevel := zerolog.InfoLevel
	if len(configs) > 0 && configs[0] != nil {
		if lvl, err := zerolog.ParseLevel(strings.ToLower(configs[0].LogLevel)); err == nil {
			logLevel = lvl
		}
	}
	return &SubordinateJWKSRefresher{
		storage: storage,
		fetch:   fetch,
		logger:  internal.Logger().Level(logLevel),
		state:   make(map[string]*subPollState),
	}, nil
}

// IsStarted reports whether Start has been called and Stop has not.
func (p *SubordinateJWKSRefresher) IsStarted() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.started
}

// Start launches polling goroutines for all enabled subordinates. The initial
// poll of each subordinate is performed synchronously; an error from any
// initial poll aborts Start after stopping already-started goroutines.
func (p *SubordinateJWKSRefresher) Start() error {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return errors.New("subordinate JWKS refresher already started")
	}
	p.stopCh = make(chan struct{})
	p.mu.Unlock()

	subs, err := p.storage.ListEnabled()
	if err != nil {
		return errors.Wrap(err, "failed to list enabled subordinates")
	}

	for i := range subs {
		sub := subs[i] // capture
		p.mu.Lock()
		p.state[sub.EntityID] = &subPollState{
			lastKnownKIDs: ExtractKIDs(sub.JWKS),
			backoff:       subInitialBackoff,
			stopCh:        make(chan struct{}),
		}
		p.mu.Unlock()

		if _, err := p.pollAndMaybeUpdate(&sub); err != nil {
			p.logger.Warn().Err(err).Str("entity_id", sub.EntityID).
				Msg("initial poll failed for subordinate; will retry in background")
		}
		p.wg.Add(1)
		go p.pollGoroutine(&sub)
	}

	p.mu.Lock()
	p.started = true
	p.mu.Unlock()
	p.logger.Info().Int("count", len(subs)).Msg("subordinate JWKS refresher started")
	return nil
}

// Stop gracefully shuts down all polling goroutines. Safe to call multiple
// times.
func (p *SubordinateJWKSRefresher) Stop() {
	p.mu.Lock()
	if !p.started {
		p.mu.Unlock()
		return
	}
	p.started = false
	close(p.stopCh)
	for _, s := range p.state {
		if s.stopCh != nil {
			close(s.stopCh)
		}
	}
	p.mu.Unlock()
	p.wg.Wait()
}

// Add registers a subordinate for polling and, if the refresher is running,
// starts polling it immediately. The initial poll is performed synchronously;
// an error is returned if it fails. If a subordinate with the same entity_id
// is already registered, its polling goroutine is stopped first and replaced.
func (p *SubordinateJWKSRefresher) Add(entityID string) error {
	if entityID == "" {
		return errors.New("cannot add subordinate without entity_id")
	}
	sub, err := p.storage.Get(entityID)
	if err != nil {
		return errors.Wrap(err, "failed to load subordinate")
	}
	if sub == nil {
		return errors.Errorf("subordinate %s not found", entityID)
	}
	if !sub.EnableJWKSUpdate {
		// Not enabled; ensure it's not being polled.
		p.Remove(entityID)
		return nil
	}

	p.mu.Lock()
	started := p.started
	if existing, ok := p.state[entityID]; ok && existing.stopCh != nil {
		close(existing.stopCh)
		delete(p.state, entityID)
	}
	p.state[entityID] = &subPollState{
		lastKnownKIDs: ExtractKIDs(sub.JWKS),
		backoff:       subInitialBackoff,
		stopCh:        make(chan struct{}),
	}
	p.mu.Unlock()

	if !started {
		return nil
	}
	if _, err := p.pollAndMaybeUpdate(sub); err != nil {
		return errors.Wrapf(err, "initial poll failed for subordinate %s", entityID)
	}
	p.wg.Add(1)
	go p.pollGoroutine(sub)
	return nil
}

// Remove stops polling for a subordinate by entity_id. No-op if not registered.
func (p *SubordinateJWKSRefresher) Remove(entityID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.state[entityID]; ok {
		if s.stopCh != nil {
			close(s.stopCh)
		}
		delete(p.state, entityID)
	}
}

// Update reloads a subordinate from storage and restarts its polling goroutine
// if it is enabled. If not enabled, any existing polling is stopped. If the
// subordinate is unknown it is added via Add.
func (p *SubordinateJWKSRefresher) Update(entityID string) error {
	p.mu.Lock()
	started := p.started
	_, exists := p.state[entityID]
	p.mu.Unlock()
	if started && exists {
		p.Remove(entityID)
	}
	return p.Add(entityID)
}

// pollGoroutine runs the polling loop for a single subordinate.
func (p *SubordinateJWKSRefresher) pollGoroutine(sub *SubordinateJWKSInfo) {
	defer p.wg.Done()

	p.mu.Lock()
	state := p.state[sub.EntityID]
	p.mu.Unlock()
	var subStopCh chan struct{}
	if state != nil {
		subStopCh = state.stopCh
	}

	var nextInterval time.Duration
	for {
		// Default the first poll to a short interval so the initial poll
		// happens promptly after Start (Start already did one synchronous poll;
		// this schedules the next one based on the EC exp).
		if nextInterval == 0 {
			nextInterval = SubMinPollInterval
		}
		select {
		case <-p.stopCh:
			return
		case <-subStopCh:
			return
		case <-time.After(nextInterval):
		}

		pollInterval, err := p.pollAndMaybeUpdate(sub)
		if err != nil {
			p.mu.Lock()
			state := p.state[sub.EntityID]
			p.mu.Unlock()
			if state != nil {
				state.mu.Lock()
				state.backoff *= 2
				if state.backoff > subMaxBackoff {
					state.backoff = subMaxBackoff
				}
				nextInterval = state.backoff
				state.mu.Unlock()
				p.logger.Warn().Err(err).Str("entity_id", sub.EntityID).
					Str("next_retry", time.Now().Add(nextInterval).Format(time.RFC3339)).
					Msg("failed to fetch EC for subordinate, retrying with backoff")
			} else {
				return // subordinate was removed
			}
		} else {
			p.mu.Lock()
			state := p.state[sub.EntityID]
			p.mu.Unlock()
			if state == nil {
				return
			}
			state.mu.Lock()
			state.backoff = subInitialBackoff
			state.mu.Unlock()
			nextInterval = pollInterval
		}
	}
}

// pollAndMaybeUpdate fetches the EC for the subordinate, verifies its signature
// against the currently stored JWKS, compares KIDs, and updates storage if the
// JWKS changed. Returns the recommended next poll interval on success.
func (p *SubordinateJWKSRefresher) pollAndMaybeUpdate(sub *SubordinateJWKSInfo) (time.Duration, error) {
	entityID := sub.EntityID

	ec, err := p.fetch(entityID)
	if err != nil {
		return 0, errors.Wrap(err, "failed to fetch EC")
	}
	// The EC MUST have a valid (future) exp; it is required by the spec and
	// the refresher derives the next poll interval from it. A zero/epoch exp
	// (which round-trips through JSON as 0) or an already-expired EC is
	// rejected.
	if ec.ExpiresAt.IsZero() || ec.ExpiresAt.Unix() == 0 || ec.ExpiresAt.Before(time.Now()) {
		return 0, errors.New("EC has no valid future exp; exp is required")
	}

	// Verify signature using the currently known JWKS, if any.
	if sub.JWKS.Set != nil && sub.JWKS.Len() > 0 {
		if !ec.Verify(sub.JWKS) {
			return 0, errors.New("EC signature verification failed against known JWKS")
		}
	}

	p.mu.Lock()
	state := p.state[entityID]
	if state == nil {
		p.mu.Unlock()
		return 0, errors.Errorf("polling state not found for subordinate %s", entityID)
	}
	state.mu.Lock()
	p.mu.Unlock()
	state.backoff = subInitialBackoff
	newKIDs := ExtractKIDs(ec.JWKS)
	changed, added, removed := HasJWKSChanged(state.lastKnownKIDs, newKIDs)

	if changed {
		if err = p.storage.UpdateJWKS(entityID, ec.JWKS); err != nil {
			p.logger.Error().Err(err).Str("entity_id", entityID).
				Msg("failed to store updated JWKS for subordinate")
		}
		state.lastKnownKIDs = newKIDs
		// Keep the in-memory copy in sync so subsequent signature verifications
		// use the new keys.
		sub.JWKS = ec.JWKS
		p.logger.Info().
			Str("entity_id", entityID).
			Strs("added", added).
			Strs("removed", removed).
			Msg("JWKS changed for subordinate")
	}
	state.mu.Unlock()

	// Per-subordinate interval wins; else derive from EC exp (+buffer), floored
	// to SubMinPollInterval.
	if sub.JWKSPollInterval != nil && *sub.JWKSPollInterval > 0 {
		return time.Duration(*sub.JWKSPollInterval) * time.Second, nil
	}
	interval := time.Until(ec.ExpiresAt.Time) + subPollBuffer
	if interval < SubMinPollInterval {
		interval = SubMinPollInterval
	}
	return interval, nil
}
