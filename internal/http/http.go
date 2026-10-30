package http

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
)

var client *resty.Client

func init() {
	client = resty.New()
	client.SetCookieJar(nil)
	// client.SetDisableWarn(true)
	client.SetRetryCount(2)
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(10))
	// Fail fast on dead or unresponsive remotes. The per-attempt budget
	// covers the whole request, but a server that never answers the response
	// headers is abandoned after 5s, an unreachable host after 3s (dial) or
	// 5s (TLS handshake). A resolve endpoint that takes this long is better
	// skipped in favor of the next endpoint or the fallback resolver.
	client.SetTimeout(15 * time.Second)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 5 * time.Second
	client.SetTransport(transport)
	// Resty's bare default retries on any operation error — including
	// timeouts, which would repeat the full 15s per-attempt budget (3x15s)
	// for a single dead endpoint. Retry only network-level errors that did
	// not time out (connection refused/reset, DNS): those already failed
	// fast and a fresh attempt may succeed. Configuring a retry condition
	// replaces the default, so a timeout is never retried.
	client.AddRetryCondition(retryCondition)
	client.SetHeader("User-Agent", "go-oidfed")
}

// retryCondition reports whether an operation error should be retried: only
// network-level errors that did not time out qualify. Timeouts are not
// retried (the remote is slow or unreachable and a retry would just burn the
// budget again; fallback and parallel resolution take over instead), and
// non-network errors (e.g. response parsing) are never retried.
func retryCondition(_ *resty.Response, err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return !netErr.Timeout()
	}
	return false
}

// SetUserAgent sets the default User-Agent header sent by all requests.
// It can be called more than once; the last value wins.
func SetUserAgent(ua string) {
	client.SetHeader("User-Agent", ua)
}

// HttpError is a type for returning the server's error response including its status code
type HttpError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	Status           int
}

// Err returns an error including the server's error response
func (e *HttpError) Err() error {
	errStr := fmt.Sprintf("http error response: %d: %s", e.Status, e.Error)
	if e.ErrorDescription != "" {
		errStr += ": " + e.ErrorDescription
	}
	return errors.New(errStr)

}

// Do returns the client, so it can be used to do requests
func Do() *resty.Client {
	return client
}

// Get performs a http GET request and parses the response into the given interface{}
func Get(url string, params url.Values, res interface{}) (*resty.Response, *HttpError, error) {
	return GetCtx(context.Background(), url, params, res)
}

// GetCtx is Get with a context; canceling the context aborts the request
// (and, for a timed-out or canceled operation, stops Resty from retrying). It
// supersedes Get for callers that need cancellation.
func GetCtx(ctx context.Context, url string, params url.Values, res interface{}) (*resty.Response, *HttpError, error) {
	resp, err := client.R().SetContext(ctx).SetQueryParamsFromValues(params).SetError(&HttpError{}).SetResult(res).Get(url)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	if errRes, ok := resp.Error().(*HttpError); ok && errRes != nil && errRes.Error != "" {
		errRes.Status = resp.RawResponse.StatusCode
		return nil, errRes, nil
	}
	return resp, nil, nil
}

// Post performs an http POST request and parses the response into the given
// interface{}
func Post(url string, req interface{}, res interface{}, headers map[string]string) (
	*resty.Response, *HttpError, error,
) {
	return PostCtx(context.Background(), url, req, res, headers)
}

// PostCtx is Post with a context; canceling the context aborts the request
// (including any Resty retry) for callers that need cancellation.
func PostCtx(
	ctx context.Context, url string, req interface{}, res interface{}, headers map[string]string,
) (*resty.Response, *HttpError, error) {
	resp, err := client.R().SetContext(ctx).SetBody(req).SetHeaders(headers).SetError(&HttpError{}).SetResult(
		res,
	).Post(url)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	if errRes, ok := resp.Error().(*HttpError); ok && errRes != nil && errRes.Error != "" {
		errRes.Status = resp.RawResponse.StatusCode
		return nil, errRes, nil
	}
	return resp, nil, nil
}
