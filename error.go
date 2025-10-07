package oidfed

// ErrorResponse is type for holding an Error including the status code
type ErrorResponse struct {
	*Error
	Status int `json:"-"`
}

// Error is type for holding an error
type Error struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Constants for some error
const (
	InvalidRequest         = "invalid_request"
	InvalidClient          = "invalid_client"
	InvalidIssuer          = "invalid_issuer"
	InvalidSubject         = "invalid_subject"
	InvalidTrustAnchor     = "invalid_trust_anchor"
	InvalidTrustChain      = "invalid_trust_chain"
	InvalidMetadata        = "invalid_metadata"
	NotFound               = "not_found"
	ServerError            = "server_error"
	TemporarilyUnavailable = "temporarily_unavailable"
	UnsupportedParameter   = "unsupported_parameter"
	EntityIDNotFound       = "entity_id_not_found"
)

// ErrorInvalidRequest returns an Error for using InvalidRequest
func ErrorInvalidRequest(description string) *Error {
	return &Error{
		Error:            InvalidRequest,
		ErrorDescription: description,
	}
}

// ErrorInvalidClient returns an Error for using InvalidClient
func ErrorInvalidClient(description string) *Error {
	return &Error{
		Error:            InvalidClient,
		ErrorDescription: description,
	}
}

// ErrorInvalidIssuer returns an Error for using InvalidIssuer
func ErrorInvalidIssuer(description string) *Error {
	return &Error{
		Error:            InvalidIssuer,
		ErrorDescription: description,
	}
}

// ErrorInvalidSubject returns an Error for using InvalidSubject
func ErrorInvalidSubject(description string) *Error {
	return &Error{
		Error:            InvalidSubject,
		ErrorDescription: description,
	}
}

// ErrorInvalidTrustAnchor returns an Error for using InvalidTrustAnchor
func ErrorInvalidTrustAnchor(description string) *Error {
	return &Error{
		Error:            InvalidTrustAnchor,
		ErrorDescription: description,
	}
}

// ErrorInvalidTrustChain returns an Error for using InvalidTrustChain
func ErrorInvalidTrustChain(description string) *Error {
	return &Error{
		Error:            InvalidTrustChain,
		ErrorDescription: description,
	}
}

// ErrorInvalidMetadata returns an Error for using InvalidMetadata
func ErrorInvalidMetadata(description string) *Error {
	return &Error{
		Error:            InvalidMetadata,
		ErrorDescription: description,
	}
}

// ErrorNotFound returns an Error for using NotFound
func ErrorNotFound(description string) *Error {
	return &Error{
		Error:            NotFound,
		ErrorDescription: description,
	}
}

// ErrorServerError returns an Error for using ServerError
func ErrorServerError(description string) *Error {
	return &Error{
		Error:            ServerError,
		ErrorDescription: description,
	}
}

// ErrorUnsupportedParameter returns an Error for using UnsupportedParameter
func ErrorUnsupportedParameter(description string) *Error {
	return &Error{
		Error:            UnsupportedParameter,
		ErrorDescription: description,
	}
}

// ErrorTemporarilyUnavailable returns an Error for using TemporarilyUnavailable
func ErrorTemporarilyUnavailable(description string) *Error {
	return &Error{
		Error:            TemporarilyUnavailable,
		ErrorDescription: description,
	}
}
