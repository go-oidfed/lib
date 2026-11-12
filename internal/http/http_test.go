package http

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// A server that never answers the response headers must fail after the
// header timeout and must not be retried (a timeout retry would just burn
// the per-attempt budget again for a dead remote).
func TestHeaderTimeoutNotRetried(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		time.Sleep(7 * time.Second) // longer than the 5s response header timeout
	}))
	defer srv.Close()

	start := time.Now()
	_, _, err := Get(srv.URL, nil, nil)
	require.Error(t, err)
	assert.Equal(t, int32(1), attempts.Load(), "a timeout must not be retried")
	elapsed := time.Since(start)
	assert.True(t, elapsed >= 4*time.Second, "expected the header timeout to fire at ~5s, got %v", elapsed)
	assert.True(t, elapsed < 7*time.Second, "the header timeout must preempt the sleeping handler, got %v", elapsed)
}

// A connection that is dropped without a response (network-level error, no
// timeout) must be retried: it already failed fast and a fresh attempt may
// succeed.
func TestFastNetworkErrorRetried(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	res := map[string]interface{}{}
	_, httpErr, err := Get(srv.URL, nil, &res)
	require.NoError(t, err)
	assert.Nil(t, httpErr)
	assert.Equal(t, int32(2), attempts.Load(), "a fast network error must be retried")
}

func init() {
	// guard against a leftover non-default UA from an earlier test in the run
	SetUserAgent("go-oidfed")
}

// redirectingServers returns a server that answers every request with a
// redirect of the given status to a second server, and the number of
// requests the second server received.
func redirectingServers(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(target.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/elsewhere", status)
	}))
	t.Cleanup(redirector.Close)
	return redirector, &reached
}

// A POST may carry a client assertion in its body; following a 307/308
// redirect would resend it to whatever the redirect names.
func TestPostDoesNotFollowRedirects(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		redirector, reached := redirectingServers(t, status)
		form := map[string]string{"client_assertion": "assertion"}
		res := map[string]interface{}{}
		_, _, err := Post(redirector.URL, form, &res, nil)
		assert.Error(t, err, "%d: Post followed the redirect", status)
		_, err = Do().R().SetFormData(form).Post(redirector.URL)
		assert.Error(t, err, "%d: a client POST followed the redirect", status)
		assert.Equal(t, int32(0), reached.Load(), "%d: the redirect target was reached", status)
	}
}

func TestGetFollowsRedirects(t *testing.T) {
	redirector, reached := redirectingServers(t, http.StatusTemporaryRedirect)
	res := map[string]interface{}{}
	_, httpErr, err := Get(redirector.URL, nil, &res)
	require.NoError(t, err)
	assert.Nil(t, httpErr)
	assert.Equal(t, int32(1), reached.Load())
}

// A POST may carry a single-use client assertion (jti); a retry would resend
// it, and the endpoint must refuse a replayed jti. A dropped connection,
// which is retried for a GET (TestFastNetworkErrorRetried), is not retried
// for a POST.
func TestPostNetworkErrorNotRetried(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()

	res := map[string]interface{}{}
	_, _, err := Post(srv.URL, map[string]string{"a": "b"}, &res, nil)
	require.Error(t, err)
	assert.Equal(t, int32(1), attempts.Load(), "Post must not be retried")

	attempts.Store(0)
	_, err = Do().R().SetFormData(map[string]string{"a": "b"}).Post(srv.URL)
	require.Error(t, err)
	assert.Equal(t, int32(1), attempts.Load(), "a client POST must not be retried")
}
