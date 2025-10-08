package oidfed

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zachmann/go-utils/sliceutils"

	"github.com/go-oidfed/lib/apimodel"
	"github.com/go-oidfed/lib/internal/utils"
	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/unixtime"
)

// ResolveResponseStorage is an interface for storing resolve responses.
type ResolveResponseStorage interface {
	// WriteJSON stores the given ResolveResponse as a JSON document for the specified subject, trust anchor, and entity types.
	WriteJSON(subject, trustAnchor string, types []string, payload ResolveResponse) error
	// WriteJWT stores the given ResolveResponse as a JWT document for the specified subject, trust anchor, and entity types.
	WriteJWT(subject, trustAnchor string, types []string, jwt func() ([]byte, error)) error
	// ReadJSON reads and unmarshalls the JSON response for the specified subject, trust anchor, and entity types.
	ReadJSON(subject, trustAnchor string, types []string) (*ResolveResponse, error)
	// ReadJWT reads the JWT response for the specified subject, trust anchor, and entity types.
	ReadJWT(subject, trustAnchor string, types []string) ([]byte, error)
	// Prune removes stored prepared responses for a trust anchor that are not
	// part of the expected set anymore (e.g., entities dropped from collection
	// or their entity type subsets changed).
	Prune(trustAnchor string, expected []ResolveResponseKey) error
}

// ResolveStore is a minimal filesystem store to persist signed resolve responses
// so they can be served as static content implementing ResolveResponseStorage.
type ResolveStore struct {
	// BaseDir where files are written.
	BaseDir string
	// StoreJWT controls whether the signed JWT is persisted.
	StoreJWT bool
	// StoreJSON controls whether the unsigned JSON is persisted.
	StoreJSON bool
}

// ResolveResponseKey identifies a prepared response by subject and entity type subset.
type ResolveResponseKey struct {
	Subject string
	Types   []string
}

// pathFor returns a deterministic path for a subject/anchor/types triple, either for json or jwt.
func (s ResolveStore) pathFor(subject, trustAnchor string, entityTypes []string, jwt bool) (string, error) {
	key := struct {
		Subject     string
		TrustAnchor string
		Types       []string
	}{
		Subject:     subject,
		TrustAnchor: trustAnchor,
		Types:       entityTypes,
	}
	h, err := utils.HashStruct(key)
	if err != nil {
		return "", err
	}
	suffix := ".json"
	if jwt {
		suffix = ".jwt"
	}
	return filepath.Join(
		s.BaseDir, "resolve", url.PathEscape(trustAnchor),
		h+suffix,
	), nil
}

// WriteJSON persists the ResolveResponse as JSON if enabled.
func (s ResolveStore) WriteJSON(subject, trustAnchor string, types []string, res ResolveResponse) error {
	if !s.StoreJSON {
		return nil
	}
	path, err := s.pathFor(subject, trustAnchor, types, false)
	if err != nil {
		return errors.Wrap(err, "mkdir")
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return errors.Wrap(os.WriteFile(path, data, 0o644), "write resolve response")
}

// WriteJWT persists the ResolveResponse as jwt if enabled.
func (s ResolveStore) WriteJWT(subject, trustAnchor string, types []string, jwt func() ([]byte, error)) error {
	if !s.StoreJWT {
		return nil
	}
	path, err := s.pathFor(subject, trustAnchor, types, true)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.Wrap(err, "mkdir")
	}
	data, err := jwt()
	if err != nil {
		return err
	}
	return errors.Wrap(os.WriteFile(path, data, 0o644), "write resolve response")
}

// ReadJSON reads and unmarshalls the JSON response file.
func (s ResolveStore) ReadJSON(subject, trustAnchor string, types []string) (*ResolveResponse, error) {
	path, err := s.pathFor(subject, trustAnchor, types, false)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "read resolve response")
	}
	var res ResolveResponse
	err = json.Unmarshal(data, &res)
	return &res, errors.Wrap(err, "unmarshal resolve response")
}

// ReadJWT reads the JWT response file.
func (s ResolveStore) ReadJWT(subject, trustAnchor string, types []string) ([]byte, error) {
	path, err := s.pathFor(subject, trustAnchor, types, true)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "read resolve response")
	}
	return data, nil
}

// Prune removes files under the trust anchor directory that are not in the expected set.
func (s ResolveStore) Prune(trustAnchor string, expected []ResolveResponseKey) error {
	dir := filepath.Join(s.BaseDir, "resolve", url.PathEscape(trustAnchor))
	// Build the set of expected file paths for both JSON and JWT variants.
	keep := make(map[string]struct{})
	for _, k := range expected {
		if p, err := s.pathFor(k.Subject, trustAnchor, k.Types, false); err == nil {
			keep[p] = struct{}{}
		}
		if p, err := s.pathFor(k.Subject, trustAnchor, k.Types, true); err == nil {
			keep[p] = struct{}{}
		}
	}
	// List directory; if it doesn't exist, nothing to prune.
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errors.Wrap(err, "read resolve dir")
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Only consider our known file types.
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".jwt") {
			continue
		}
		full := filepath.Join(dir, name)
		if _, ok := keep[full]; !ok {
			if err = os.Remove(full); err != nil && !os.IsNotExist(err) {
				log.WithError(err).WithField("file", full).Error("ProactiveResolver: prune remove error")
			}
		}
	}
	return nil
}

// ProactiveResolver schedules proactive resolve response creation and refresh.
type ProactiveResolver struct {
	// EntityID is the issuer of the resolve response.
	EntityID string
	// Store persists signed responses.
	Store ResolveResponseStorage
	// Signer used to sign resolve responses.
	Signer *jwx.ResolveResponseSigner
	// RefreshLead defines how far ahead of expiration we refresh.
	RefreshLead time.Duration
	// Concurrency limits simultaneous resolve jobs.
	Concurrency int
	// QueueSize configures the job channel buffer; if <= 0, the channel is
	// unbuffered and producers will block until a worker receives.
	QueueSize int

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	jobs    chan apimodel.ResolveRequest
}

// Start launches the internal workers.
func (r *ProactiveResolver) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return
	}
	if r.RefreshLead <= 0 {
		r.RefreshLead = ResolverCacheGracePeriod
	}
	r.stopCh = make(chan struct{})
	if r.QueueSize <= 0 {
		r.jobs = make(chan apimodel.ResolveRequest)
	} else {
		r.jobs = make(chan apimodel.ResolveRequest, r.QueueSize)
	}
	conc := r.Concurrency
	if conc <= 0 {
		conc = 8
	}
	for i := 0; i < conc; i++ {
		go r.worker()
	}
	r.started = true
}

// Stop stops workers.
func (r *ProactiveResolver) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		return
	}
	close(r.stopCh)
	close(r.jobs)
	r.started = false
}

// Enqueue adds a resolve job.
func (r *ProactiveResolver) Enqueue(req apimodel.ResolveRequest) {
	r.Start()
	// Block until the request is accepted by a worker; ensures no drops.
	r.jobs <- req
}

func (r *ProactiveResolver) worker() {
	for {
		select {
		case <-r.stopCh:
			return
		case req, ok := <-r.jobs:
			if !ok {
				return
			}
			r.process(req)
		}
	}
}

func (r *ProactiveResolver) process(req apimodel.ResolveRequest) {
	// Resolve locally to compute payload and trust marks.
	payload, err := DefaultMetadataResolver.ResolveResponsePayload(req)
	if err != nil {
		log.WithError(err).WithField("request", req).Error("ProactiveResolver: resolve error")
		return
	}

	exp := r.earliestChainExpiry(payload.TrustChain)
	selectedTrustAnchor := payload.TrustAnchor

	// Build resolve response for signing.
	res := ResolveResponse{
		Issuer:                 r.EntityID,
		Subject:                req.Subject,
		IssuedAt:               unixtime.Now(),
		ExpiresAt:              exp,
		ResolveResponsePayload: payload,
	}
	if err = r.Store.WriteJSON(req.Subject, selectedTrustAnchor, req.EntityTypes, res); err != nil {
		log.WithError(err).Error("ProactiveResolver: error writing json resolve response")
		return
	}
	if err = r.Store.WriteJWT(
		req.Subject, selectedTrustAnchor, req.EntityTypes, func() ([]byte, error) {
			// Sign using federation signer.
			if r.Signer == nil {
				return nil, errors.New("ProactiveResolver: no signer configured")
			}
			jwtData, err := r.Signer.JWT(res)
			if err != nil {
				return nil, errors.Wrap(err, "ProactiveResolver: error signing resolve response")
			}
			return jwtData, nil
		},
	); err != nil {
		log.WithError(err).Error("ProactiveResolver: error writing jwt resolve response")
		return
	}

	// Schedule refresh ahead of expiration.
	refreshAt := exp.Time.Add(-r.RefreshLead)
	if time.Until(refreshAt) > 0 {
		go func(d time.Duration, rreq apimodel.ResolveRequest) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				r.Enqueue(rreq)
			case <-r.stopCh:
				return
			}
		}(time.Until(refreshAt), req)
	}
}

// earliestChainExpiry returns the minimum exp across all entity statements in the chain.
func (r *ProactiveResolver) earliestChainExpiry(chain JWSMessages) unixtime.Unixtime {
	var min unixtime.Unixtime
	for _, msg := range chain {
		es, err := ParseEntityStatement(msg.RawJWT)
		if err != nil || es == nil || es.ExpiresAt.IsZero() {
			continue
		}
		if min.IsZero() || es.ExpiresAt.Before(min.Time) {
			min = es.ExpiresAt
		}
	}
	return min
}

// OnDiscoveredEntities enqueues resolve jobs for each discovered entity.
func (r *ProactiveResolver) OnDiscoveredEntities(trustAnchor string, entities []*CollectedEntity) {
	var expected []ResolveResponseKey
	for _, e := range entities {
		entityTypeSubsets := sliceutils.Subsets(e.EntityTypes)
		for _, entityTypes := range entityTypeSubsets {
			req := apimodel.ResolveRequest{
				Subject:     e.EntityID,
				TrustAnchor: []string{trustAnchor},
				EntityTypes: entityTypes,
			}
			r.Enqueue(req)
			expected = append(
				expected, ResolveResponseKey{
					Subject: e.EntityID,
					Types:   entityTypes,
				},
			)
		}
	}
	if r.Store != nil {
		if err := r.Store.Prune(trustAnchor, expected); err != nil {
			log.WithError(err).WithField("trust_anchor", trustAnchor).Error("ProactiveResolver: prune error")
		}
	}
}
