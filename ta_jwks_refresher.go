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

	taState map[string]*pollState // Internal, keyed by EntityID
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

type pollState struct {
	LastKnownKIDs *strset.Set
	backoff       time.Duration
	mu            sync.RWMutex
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

	// Validate all TAs with EnableJWKSUpdate=true have valid JWKS
	for _, ta := range *p.trustAnchors {
		if !ta.EnableJWKSUpdate {
			continue
		}

		jwks := ta.JWKS()
		if jwks.Set == nil || jwks.Len() == 0 {
			return errors.Errorf("TA %s has enable_jwks_update=true but no JWKS available", ta.EntityID)
		}

		// Initialize poll state
		p.taState[ta.EntityID] = &pollState{
			LastKnownKIDs: extractKIDs(jwks),
			backoff:       initialBackoff,
		}

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

// pollGoroutine runs the polling loop for a single TA
func (p *TAJWKSRefresher) pollGoroutine(ta *TrustAnchor) {
	defer p.wg.Done()

	p.logger.WithField("entity_id", ta.EntityID).Debug("Starting TA key polling")

	var nextInterval time.Duration

	for {
		select {
		case <-p.stopCh:
			return
		case <-time.After(nextInterval):
		}

		pollInterval, err := p.pollAndMaybeUpdate(ta)
		if err != nil {
			state := p.taState[ta.EntityID]
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
			state := p.taState[ta.EntityID]
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

	state := p.taState[ta.EntityID]
	if state == nil {
		return 0, errors.Errorf("polling state not found for TA %s", ta.EntityID)
	}
	state.mu.Lock()
	state.backoff = initialBackoff
	newKIDs := extractKIDs(ec.JWKS)
	changed, added, removed := hasJWKSChanged(p.taState[entityID].LastKnownKIDs, newKIDs)

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
	for i := range jwks.Len() {
		key, _ := jwks.Key(i)
		if kid, ok := key.KeyID(); ok && kid != "" {
			kids.Add(kid)
		}
	}
	return kids
}
