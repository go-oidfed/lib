package oidfed

import (
	"github.com/go-oidfed/lib/internal/http"
)

// SetDefaultUserAgent sets the default User-Agent header sent on all outgoing requests.
// Consumers should set this to a recognizable string identifying their product, e.g. "LightHouse 1.2.3".
// It can be called more than once; the last value wins.
func SetDefaultUserAgent(ua string) {
	http.SetUserAgent(ua)
}
