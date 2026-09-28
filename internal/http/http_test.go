package http

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestDefaultUserAgent(t *testing.T) {
	var mu sync.Mutex
	got := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Get("User-Agent")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	res := map[string]interface{}{}
	if _, httpErr, err := Get(srv.URL, nil, &res); err != nil {
		t.Fatalf("Get failed: %v", err)
	} else if httpErr != nil {
		t.Fatalf("Get returned http error: %+v", httpErr)
	}

	mu.Lock()
	defer mu.Unlock()
	if got != "go-oidfed" {
		t.Fatalf("default User-Agent = %q, want %q", got, "go-oidfed")
	}
}

func TestSetUserAgent(t *testing.T) {
	cases := []string{"LightHouse 1.2.3", "custom/2.0 (https://example.org)"}
	for _, ua := range cases {
		SetUserAgent(ua)
		var mu sync.Mutex
		got := ""
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			got = r.Header.Get("User-Agent")
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}))

		res := map[string]interface{}{}
		if _, httpErr, err := Get(srv.URL, nil, &res); err != nil {
			srv.Close()
			t.Fatalf("Get failed: %v", err)
		} else if httpErr != nil {
			srv.Close()
			t.Fatalf("Get returned http error: %+v", httpErr)
		}
		srv.Close()

		mu.Lock()
		if got != ua {
			t.Fatalf("User-Agent = %q, want %q", got, ua)
		}
		mu.Unlock()
	}
	// restore default so other tests are unaffected
	SetUserAgent("go-oidfed")
}

func init() {
	// guard against a leftover non-default UA from an earlier test in the run
	SetUserAgent("go-oidfed")
}
