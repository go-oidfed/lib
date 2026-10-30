package apimodel

import "context"

// ResolveRequest is a request to the resolve endpoint
type ResolveRequest struct {
	Subject     string   `json:"sub" form:"sub" query:"sub" url:"sub"`
	TrustAnchor []string `json:"trust_anchor" form:"trust_anchor" query:"trust_anchor" url:"trust_anchor"`
	EntityTypes []string `json:"entity_type" form:"entity_type" query:"entity_type" url:"entity_type"`
	// Context, when non-nil, bounds and cancels the resolution (e.g. a
	// request deadline or client disconnect). It is never serialized.
	Context context.Context `json:"-" form:"-" query:"-" url:"-"`
}
