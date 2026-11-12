package oidfed

import (
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/jarcoal/httpmock"

	"github.com/go-oidfed/lib/apimodel"
)

// listErrorRecorder collects the errors reported through OnListError.
type listErrorRecorder struct {
	mu   sync.Mutex
	errs map[string]error
}

func (r *listErrorRecorder) hook(authority string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.errs == nil {
		r.errs = make(map[string]error)
	}
	r.errs[authority] = err
}

func (r *listErrorRecorder) refusal(t *testing.T, authority string) *ListRefusedError {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var refused *ListRefusedError
	if err, ok := r.errs[authority]; !ok {
		t.Fatalf("no list error reported for %s, got %v", authority, r.errs)
	} else if !errors.As(err, &refused) {
		t.Fatalf("list error for %s is %T (%v), want *ListRefusedError", authority, err, err)
	}
	return refused
}

func refuseList(a *mockAuthority, status int) {
	httpmock.RegisterResponder(
		"GET", a.ListEndpoint,
		httpmock.NewJsonResponderOrPanic(
			status, map[string]string{"error": "access_denied", "error_description": "list not published"},
		),
	)
}

func TestCollectorReportsRefusedTrustAnchorList(t *testing.T) {
	leaf := newMockAuthority("https://leaf-ta-refused.example", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-refused.example", EntityStatementPayload{})
	ta.RegisterSubordinate(leaf)
	refuseList(ta, http.StatusUnauthorized)

	var rec listErrorRecorder
	res, errRes := (&SimpleEntityCollector{OnListError: rec.hook}).CollectEntities(
		apimodel.EntityCollectionRequest{TrustAnchor: ta.EntityID},
	)
	if errRes != nil {
		t.Fatalf("unexpected error: %+v", errRes)
	}
	if len(res.Entities) != 0 {
		t.Fatalf("expected an empty collection, got %d entities", len(res.Entities))
	}
	got := rec.refusal(t, ta.EntityID)
	if got.Authority != ta.EntityID || got.Status != http.StatusUnauthorized {
		t.Fatalf("got %+v, want authority %s status 401", got, ta.EntityID)
	}
}

func TestCollectorReportsRefusedIntermediateList(t *testing.T) {
	leafA := newMockAuthority("https://leaf-a-inter.example", EntityStatementPayload{})
	leafB := newMockAuthority("https://leaf-b-inter.example", EntityStatementPayload{})
	inter := newMockAuthority("https://inter-refused.example", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-inter.example", EntityStatementPayload{})
	ta.RegisterSubordinate(leafA)
	ta.RegisterSubordinate(inter)
	inter.RegisterSubordinate(leafB)
	refuseList(inter, http.StatusForbidden)

	var rec listErrorRecorder
	res, errRes := (&SimpleEntityCollector{OnListError: rec.hook}).CollectEntities(
		apimodel.EntityCollectionRequest{TrustAnchor: ta.EntityID},
	)
	if errRes != nil {
		t.Fatalf("unexpected error: %+v", errRes)
	}
	ids := make(map[string]bool)
	for _, e := range res.Entities {
		ids[e.EntityID] = true
	}
	if len(ids) != 2 || !ids[leafA.EntityID] || !ids[inter.EntityID] {
		t.Fatalf("expected the leaf and the intermediate, got %v", ids)
	}
	got := rec.refusal(t, inter.EntityID)
	if got.Authority != inter.EntityID || got.Status != http.StatusForbidden {
		t.Fatalf("got %+v, want authority %s status 403", got, inter.EntityID)
	}
}

func TestCollectorNilHookUnchanged(t *testing.T) {
	leaf := newMockAuthority("https://leaf-nil.example", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-nil.example", EntityStatementPayload{})
	ta.RegisterSubordinate(leaf)
	refuseList(ta, http.StatusUnauthorized)

	res, errRes := (&SimpleEntityCollector{}).CollectEntities(
		apimodel.EntityCollectionRequest{TrustAnchor: ta.EntityID},
	)
	if errRes != nil {
		t.Fatalf("unexpected error: %+v", errRes)
	}
	if res == nil || len(res.Entities) != 0 {
		t.Fatalf("expected an empty collection, got %+v", res)
	}
}

func TestCollectorReportsListThatAdvertisesAuth(t *testing.T) {
	ta := newMockAuthority("https://ta-auth.example", EntityStatementPayload{})
	ta.data.Metadata.FederationEntity.FederationListEndpointAuthMethods = []string{"private_key_jwt"}
	httpmock.RegisterResponder(
		"GET", ta.ListEndpoint, httpmock.NewStringResponder(500, "must not be requested"),
	)

	var rec listErrorRecorder
	res, _ := (&SimpleEntityCollector{OnListError: rec.hook}).CollectEntities(
		apimodel.EntityCollectionRequest{TrustAnchor: ta.EntityID},
	)
	if len(res.Entities) != 0 {
		t.Fatalf("expected an empty collection, got %d entities", len(res.Entities))
	}
	if got := rec.refusal(t, ta.EntityID); got.Status != 0 {
		t.Fatalf("got %+v, want status 0", got)
	}
}

func refuseCollection(endpoint string, status int) {
	httpmock.RegisterResponder(
		"GET", endpoint,
		httpmock.NewJsonResponderOrPanic(status, map[string]string{"error": "access_denied"}),
	)
}

func TestCollectorRecoveredCollectionRefusalNotReported(t *testing.T) {
	leaf := newMockAuthority("https://leaf-recovered.example", EntityStatementPayload{})
	sub := newMockAuthority("https://sub-recovered.example", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-recovered.example", EntityStatementPayload{})
	ta.RegisterSubordinate(sub)
	sub.RegisterSubordinate(leaf)
	sub.data.Metadata.FederationEntity.FederationCollectionEndpoint = "https://sub-recovered.example/collect"
	refuseCollection("https://sub-recovered.example/collect", http.StatusForbidden)

	var rec listErrorRecorder
	res, errRes := (&SimpleEntityCollector{OnListError: rec.hook}).CollectEntities(
		apimodel.EntityCollectionRequest{TrustAnchor: ta.EntityID},
	)
	if errRes != nil {
		t.Fatalf("unexpected error: %+v", errRes)
	}
	ids := make(map[string]bool)
	for _, e := range res.Entities {
		ids[e.EntityID] = true
	}
	if !ids[sub.EntityID] || !ids[leaf.EntityID] {
		t.Fatalf("expected the subordinate and its member via the list endpoint, got %v", ids)
	}
	if len(rec.errs) != 0 {
		t.Fatalf("a recovered refusal must not be reported, got %v", rec.errs)
	}
}

func TestCollectorReportsRefusedCollectionWithoutList(t *testing.T) {
	sub := newMockAuthority("https://sub-nolist.example", EntityStatementPayload{})
	ta := newMockAuthority("https://ta-nolist.example", EntityStatementPayload{})
	ta.RegisterSubordinate(sub)
	sub.data.Metadata.FederationEntity.FederationListEndpoint = ""
	sub.data.Metadata.FederationEntity.FederationCollectionEndpoint = "https://sub-nolist.example/collect"
	refuseCollection("https://sub-nolist.example/collect", http.StatusUnauthorized)

	var rec listErrorRecorder
	if _, errRes := (&SimpleEntityCollector{OnListError: rec.hook}).CollectEntities(
		apimodel.EntityCollectionRequest{TrustAnchor: ta.EntityID},
	); errRes != nil {
		t.Fatalf("unexpected error: %+v", errRes)
	}
	if got := rec.refusal(t, sub.EntityID); got.Status != http.StatusUnauthorized {
		t.Fatalf("got %+v, want status 401", got)
	}
}

func TestListAuthRequired(t *testing.T) {
	old := DefaultClientAuth
	t.Cleanup(func() { DefaultClientAuth = old })
	cases := []struct {
		name    string
		methods []string
		auth    bool
		want    bool
	}{
		{"none advertised", nil, false, false},
		{"explicit none", []string{"none", "private_key_jwt"}, false, false},
		{"private_key_jwt, no producer", []string{"private_key_jwt"}, false, true},
		{"private_key_jwt, producer set", []string{"private_key_jwt"}, true, false},
		{"other method, producer set", []string{"client_secret_basic"}, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			DefaultClientAuth = nil
			if c.auth {
				DefaultClientAuth = &RequestObjectProducer{}
			}
			if got := listAuthRequired(c.methods); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}
