package oidfed

import (
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/scylladb/go-set/strset"
	"github.com/sirupsen/logrus"

	"github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/jwx"
)

const (
	pollBuffer          = 1 * time.Second
	defaultPollInterval = 1 * time.Hour
	initialBackoff      = 1 * time.Second
	maxBackoff          = 5 * time.Minute
)

// TAJWKSRefresherConfig configures the TA key polling behavior
type TAJWKSRefresherConfig struct {
	// LogLevel sets minimum log level ("debug", "info", "warn", "error")
	// Default: "info"
	LogLevel string `yaml:"log_level"`
}

// TAJWKSRefresher monitors trust anchors for JWKS changes and updates them automatically
type TAJWKSRefresher struct {
	trustAnchors *TrustAnchors
	storage      JWKStorage
	logger       logrus.FieldLogger

	mu      sync.Mutex            // guards trustAnchors slice and taState map for concurrent Add/Remove/Update
	taState map[string]*pollState // Internal, keyed by EntityID
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

type pollState struct {
	LastKnownKIDs *strset.Set
	backoff       time.Duration
	mu            sync.RWMutex
	stopCh        chan struct{} // per-TA stop channel; closed by Remove to stop a single goroutine
}

// NewTAJWKSRefresher creates a new TA key poller
// Accepts 0 or 1 config structs (uses first if multiple passed)
// Default log level is "info"
func NewTAJWKSRefresher(
	tas *TrustAnchors,
	storage JWKStorage,
	configs ...*TAJWKSRefresherConfig,
) (*TAJWKSRefresher, error) {
	logLevel := logrus.InfoLevel

	if len(configs) > 0 && configs[0] != nil {
		level, err := logrus.ParseLevel(strings.ToLower(configs[0].LogLevel))
		if err == nil {
			logLevel = level
		}
	}
	logger := internal.Logger()
	// TODO the refresher logger should use another log level
	_ = logLevel

	refresher := &TAJWKSRefresher{
		trustAnchors: tas,
		storage:      storage,
		logger:       logger,
		taState:      make(map[string]*pollState),
	}

	// Register explicit jwks_file paths for enabled TAs
	for _, ta := range *tas {
		if ta.EnableJWKSUpdate && ta.JWKSFile != "" {
			if err := storage.RegisterEntityJWKSFile(ta.EntityID, ta.JWKSFile); err != nil {
				return nil, errors.Wrapf(
					err, "could not register entity's %q jwks_file %q in storage", ta.EntityID, ta.JWKSFile,
				)
			}
		}
	}

	return refresher, nil
}

// Start launches the polling goroutines for all TAs with EnableJWKSUpdate=true
// Returns an error if initial validation fails
func (p *TAJWKSRefresher) Start() error {
	p.stopCh = make(chan struct{})

	// Merge config JWKS with stored JWKS for all TAs with EnableJWKSUpdate=true
	for _, ta := range *p.trustAnchors {
		if !ta.EnableJWKSUpdate {
			continue
		}
		if p.storage == nil {
			continue
		}

		storedJWKS, err := p.storage.GetJWKS(ta.EntityID)
		if err != nil {
			p.logger.WithError(err).WithField("entity_id", ta.EntityID).
				Warn("Failed to load stored JWKS, using config JWKS only")
		}
		if storedJWKS != nil && storedJWKS.Set != nil && storedJWKS.Len() > 0 {
			configJWKS := ta.JWKS()
			if configJWKS.Set != nil && configJWKS.Len() > 0 {
				merged := jwx.MergeJWKS(configJWKS, *storedJWKS)
				ta.SetJWKS(merged)
				p.logger.WithFields(
					logrus.Fields{
						"entity_id":   ta.EntityID,
						"config_keys": configJWKS.Len(),
						"stored_keys": storedJWKS.Len(),
						"merged_keys": merged.Len(),
					},
				).Info("Merged config and stored JWKS for TA on startup")
			} else {
				ta.SetJWKS(*storedJWKS)
			}
		}
	}

	// Validate all TAs with EnableJWKSUpdate=true have valid JWKS, unless
	// storage is available to seed the JWKS from the first poll (first-poll-seed).
	for _, ta := range *p.trustAnchors {
		if !ta.EnableJWKSUpdate {
			continue
		}

		jwks := ta.JWKS()
		if jwks.Set == nil || jwks.Len() == 0 {
			if p.storage == nil {
				return errors.Errorf("TA %s has enable_jwks_update=true but no JWKS available", ta.EntityID)
			}
			// No JWKS yet but storage is available: the initial poll will fetch
			// the EC and seed the JWKS. Skip the validation error.
			p.logger.WithField("entity_id", ta.EntityID).
				Info("TA has no JWKS; will seed from first poll")
		}

		// Initialize poll state
		p.mu.Lock()
		p.taState[ta.EntityID] = &pollState{
			LastKnownKIDs: extractKIDs(jwks),
			backoff:       initialBackoff,
			stopCh:        make(chan struct{}),
		}
		p.mu.Unlock()

		// Perform initial fetch and update
		if _, err := p.pollAndMaybeUpdate(ta); err != nil {
			return errors.Wrapf(err, "initial poll failed for TA %s", ta.EntityID)
		}

		p.wg.Add(1)
		go p.pollGoroutine(ta)
	}

	return nil
}

// Stop gracefully shuts down all polling goroutines
func (p *TAJWKSRefresher) Stop() {
	if p.stopCh != nil {
		close(p.stopCh)
	}
	p.wg.Wait()
}

// IsStarted reports whether the refresher has been started (Start called and
// not yet stopped). Safe to call concurrently with Start/Stop.
func (p *TAJWKSRefresher) IsStarted() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopCh != nil
}

// Add adds a trust anchor to the refresher and, if the refresher is running and
// the TA has EnableJWKSUpdate=true, starts polling it immediately. If a TA with
// the same entity_id already exists, it is replaced (its polling goroutine is
// stopped first). The initial poll is performed synchronously; an error is
// returned if it fails (unless the TA has no JWKS and storage is available to
// seed — then the error from a failed initial fetch is returned but the TA is
// still registered).
//
// This is safe to call after Start(); it is the dynamic per-TA control used by
// the admin API.
func (p *TAJWKSRefresher) Add(ta *TrustAnchor) error {
	if ta == nil || ta.EntityID == "" {
		return errors.New("cannot add nil trust anchor or one without entity_id")
	}
	p.mu.Lock()
	started := p.stopCh != nil
	// Stop existing polling goroutine for this entity_id, if any.
	if existing, ok := p.taState[ta.EntityID]; ok && existing.stopCh != nil {
		close(existing.stopCh)
		delete(p.taState, ta.EntityID)
	}
	// Replace or append in the slice.
	replaced := false
	for i, existing := range *p.trustAnchors {
		if existing.EntityID == ta.EntityID {
			(*p.trustAnchors)[i] = ta
			replaced = true
			break
		}
	}
	if !replaced {
		*p.trustAnchors = append(*p.trustAnchors, ta)
	}
	p.mu.Unlock()

	if !ta.EnableJWKSUpdate || !started {
		return nil
	}

	// Initialize poll state and start polling.
	p.mu.Lock()
	p.taState[ta.EntityID] = &pollState{
		LastKnownKIDs: extractKIDs(ta.JWKS()),
		backoff:       initialBackoff,
		stopCh:        make(chan struct{}),
	}
	p.mu.Unlock()

	if _, err := p.pollAndMaybeUpdate(ta); err != nil {
		return errors.Wrapf(err, "initial poll failed for TA %s", ta.EntityID)
	}
	p.wg.Add(1)
	go p.pollGoroutine(ta)
	return nil
}

// Remove stops polling for and removes a trust anchor by entity_id. If the TA
// does not exist, this is a no-op. Safe to call after Start().
func (p *TAJWKSRefresher) Remove(entityID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if state, ok := p.taState[entityID]; ok {
		if state.stopCh != nil {
			close(state.stopCh)
		}
		delete(p.taState, entityID)
	}
	// Remove from the slice.
	filtered := (*p.trustAnchors)[:0]
	for _, ta := range *p.trustAnchors {
		if ta.EntityID != entityID {
			filtered = append(filtered, ta)
		}
	}
	*p.trustAnchors = filtered
}

// Update replaces an existing trust anchor with an updated one, restarting its
// polling goroutine if poll-relevant fields changed. If the TA does not exist,
// it is added via Add. Safe to call after Start().
func (p *TAJWKSRefresher) Update(ta *TrustAnchor) error {
	if ta == nil || ta.EntityID == "" {
		return errors.New("cannot update nil trust anchor or one without entity_id")
	}
	p.mu.Lock()
	_, exists := p.taState[ta.EntityID]
	p.mu.Unlock()
	if !exists {
		// Not currently registered; check if it's in the slice at all.
		found := false
		for _, existing := range *p.trustAnchors {
			if existing.EntityID == ta.EntityID {
				found = true
				break
			}
		}
		if !found {
			return p.Add(ta)
		}
	}
	// Stop the existing goroutine then Add the updated TA.
	p.Remove(ta.EntityID)
	return p.Add(ta)
}

// pollGoroutine runs the polling loop for a single TA
func (p *TAJWKSRefresher) pollGoroutine(ta *TrustAnchor) {
	defer p.wg.Done()

	p.logger.WithField("entity_id", ta.EntityID).Debug("Starting TA key polling")

	var nextInterval time.Duration

	// Per-TA stop channel; nil if not present (e.g. started via Start before
	// per-TA channels existed). We select on it additionally so Remove can
	// stop this single goroutine.
	p.mu.Lock()
	state := p.taState[ta.EntityID]
	p.mu.Unlock()
	var taStopCh chan struct{}
	if state != nil {
		taStopCh = state.stopCh
	}

	for {
		select {
		case <-p.stopCh:
			return
		case <-taStopCh:
			return
		case <-time.After(nextInterval):
		}

		pollInterval, err := p.pollAndMaybeUpdate(ta)
		if err != nil {
			p.mu.Lock()
			state := p.taState[ta.EntityID]
			p.mu.Unlock()
			if state != nil {
				state.mu.Lock()
				// Exponential backoff: multiply by 2, cap at maxBackoff
				state.backoff *= 2
				if state.backoff > maxBackoff {
					state.backoff = maxBackoff
				}
				nextInterval = state.backoff
				state.mu.Unlock()

				p.logger.WithError(err).WithFields(
					logrus.Fields{
						"entity_id":  ta.EntityID,
						"next_retry": time.Now().Add(nextInterval).Format(time.RFC3339),
					},
				).Warn("Failed to fetch EC for TA, retrying with backoff")
			}
		} else {
			// Reset backoff on success
			p.mu.Lock()
			state := p.taState[ta.EntityID]
			p.mu.Unlock()
			if state != nil {
				state.mu.Lock()
				state.backoff = initialBackoff
				state.mu.Unlock()
			}
			nextInterval = pollInterval
		}
	}
}

// pollAndMaybeUpdate fetches the EC and updates JWKS if changed
// Returns the recommended next poll interval on success
func (p *TAJWKSRefresher) pollAndMaybeUpdate(ta *TrustAnchor) (time.Duration, error) {
	entityID := ta.EntityID

	// Fetch entity configuration
	ec, err := GetEntityConfiguration(entityID)
	if err != nil {
		return 0, errors.Wrap(err, "failed to fetch EC")
	}

	p.logger.WithFields(
		logrus.Fields{
			"entity_id": entityID,
			"keys":      ec.JWKS.Len(),
		},
	).Debug("Fetched EC for TA")

	// Verify signature using current JWKS
	currentJWKS := ta.JWKS()
	if currentJWKS.Set != nil && currentJWKS.Len() > 0 {
		if !ec.Verify(currentJWKS) {
			return 0, errors.New("EC signature verification failed")
		}
	}

	p.mu.Lock()
	state := p.taState[ta.EntityID]
	if state == nil {
		p.mu.Unlock()
		return 0, errors.Errorf("polling state not found for TA %s", ta.EntityID)
	}
	state.mu.Lock()
	p.mu.Unlock()
	state.backoff = initialBackoff
	newKIDs := extractKIDs(ec.JWKS)
	changed, added, removed := hasJWKSChanged(state.LastKnownKIDs, newKIDs)

	if changed {
		// Update storage
		if p.storage != nil {
			if err = p.storage.UpdateJWKS(entityID, ec.JWKS); err != nil {
				p.logger.WithError(err).WithField("entity_id", entityID).Error("Failed to store updated JWKS")
			}
		}
		// Update TA's atomic JWKS
		ta.SetJWKS(ec.JWKS)

		state.LastKnownKIDs = newKIDs

		// Log the change
		p.logger.WithFields(
			logrus.Fields{
				"entity_id": entityID,
				"added":     added,
				"removed":   removed,
			},
		).Info("JWKS changed for TA")
	}
	state.mu.Unlock()

	// Compute next poll interval
	// User-configured interval always takes precedence
	if ta.KeyPollInterval.Duration() > 0 {
		return ta.KeyPollInterval.Duration(), nil
	}

	// Use EC's expiration if available
	if !ec.ExpiresAt.IsZero() {
		interval := time.Until(ec.ExpiresAt.Time) + pollBuffer
		if interval > 0 {
			return interval, nil
		}
	}

	// Fallback default
	return defaultPollInterval, nil
}

// hasJWKSChanged compares two JWKS and returns whether they differ based on KIDs
// Returns: changed, addedKIDs, removedKIDs
func hasJWKSChanged(oldJWKS, newJWKS *strset.Set) (bool, []string, []string) {
	removed := strset.Difference(oldJWKS, newJWKS).List()
	added := strset.Difference(newJWKS, oldJWKS).List()
	change := false
	if len(added) > 0 {
		change = true
	} else {
		added = nil
	}
	if len(removed) > 0 {
		change = true
	} else {
		removed = nil
	}
	return change, added, removed
}

// extractKIDs extracts all KIDs from a JWKS
func extractKIDs(jwks jwx.JWKS) *strset.Set {
	kids := strset.New()
	if jwks.Set == nil {
		return kids
	}
	for i := range jwks.Len() {
		key, _ := jwks.Key(i)
		if kid, ok := key.KeyID(); ok && kid != "" {
			kids.Add(kid)
		}
	}
	return kids
}
