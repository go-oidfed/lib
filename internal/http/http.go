package http

import (
	"fmt"
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
	client.SetTimeout(20 * time.Second)
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
	resp, err := client.R().SetQueryParamsFromValues(params).SetError(&HttpError{}).SetResult(res).Get(url)
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
	resp, err := client.R().SetBody(req).SetHeaders(headers).SetError(&HttpError{}).SetResult(
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
