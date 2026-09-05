package authkit

import (
	"encoding/json"
	"net/http"

	"github.com/open-rails/authkit/internal/errmodel"
)

// Stripe-style HTTP error envelope, shared by authhttp and the core-free verify
// package so both surfaces emit an identical shape. Structurally identical to
// openrails' pkg/api.ErrorResponse (the ecosystem-wide error contract): the
// machine-readable `code` is stable, `type` categorizes it, `message` is human
// readable, and `param`/`metadata` carry optional context.

// Error type categories, aligned with openrails' / Stripe's taxonomy strings.
const (
	ErrorTypeInvalidRequest = "invalid_request_error"
	ErrorTypeAuthentication = "authentication_error"
	ErrorTypeAuthorization  = "authorization_error"
	ErrorTypeRateLimit      = "rate_limit_error"
	ErrorTypeAPI            = "api_error"
)

// ErrorObject is the nested error detail carried under the top-level "error" key.
type ErrorObject struct {
	Type     string         `json:"type"`
	Code     string         `json:"code"`
	Message  string         `json:"message"`
	Param    *string        `json:"param,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ErrorEnvelope is the top-level error response: {"error": {...}}.
type ErrorEnvelope struct {
	Error ErrorObject `json:"error"`
}

// ErrorTypeForStatus maps an HTTP status to its error-type category (the same
// inference openrails performs).
func ErrorTypeForStatus(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return ErrorTypeAuthentication
	case http.StatusForbidden:
		return ErrorTypeAuthorization
	case http.StatusTooManyRequests:
		return ErrorTypeRateLimit
	}
	if status >= 500 {
		return ErrorTypeAPI
	}
	return ErrorTypeInvalidRequest // 400/404/409 and other 4xx
}

// ErrorEnvelopeFor derives the wire status and envelope for err: an *Error
// keeps its status, code, param (the catalog's default when unset) and
// metadata; a plain 500 — and anything that is not an *Error — is emitted as
// internal_error, so the operation name never reaches the wire.
func ErrorEnvelopeFor(err error) (int, ErrorEnvelope) {
	e := AsError(err)
	if e == nil {
		return http.StatusInternalServerError, envelope(http.StatusInternalServerError, CodeInternalError, "", nil)
	}
	status := e.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	code := e.Code
	if status == http.StatusInternalServerError {
		code = CodeInternalError
	}
	param := e.Param
	if param == "" {
		param = errmodel.DefaultParam(code)
	}
	return status, envelope(status, code, param, e.Meta)
}

func envelope(status int, code Code, param string, metadata map[string]any) ErrorEnvelope {
	_, message, _ := errmodel.Describe(code)
	if message == "" {
		message = "Request failed."
	}
	var p *string
	if param != "" {
		p = &param
	}
	if len(metadata) == 0 {
		metadata = nil
	}
	return ErrorEnvelope{Error: ErrorObject{Type: ErrorTypeForStatus(status), Code: string(code), Message: message, Param: p, Metadata: metadata}}
}

// WriteError writes err as the canonical error envelope — the ONE writer
// behind authhttp and verify.
func WriteError(w http.ResponseWriter, err error) {
	status, env := ErrorEnvelopeFor(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}
