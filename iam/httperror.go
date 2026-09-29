package iam

import (
	"encoding/json"
	"net/http"

	"github.com/open-rails/authkit/internal/errmodel"
)

// ErrorObject is the error detail under the envelope's "error" key: a stable
// code, its type category, a human-readable message, and optional param and
// metadata. The shape matches openrails' pkg/api.ErrorResponse.
type ErrorObject struct {
	Type     string         `json:"type"`
	Code     string         `json:"code"`
	Message  string         `json:"message"`
	Param    *string        `json:"param,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ErrorEnvelope is every AuthKit error response: {"error": {...}}.
type ErrorEnvelope struct {
	Error ErrorObject `json:"error"`
}

// WriteError writes err as the error envelope with the catalog's status for
// its code. Anything that is not an AuthKit error, and every server failure,
// is written as 500 internal_error.
func WriteError(w http.ResponseWriter, err error) {
	e := errmodel.Wire(err)
	var param *string
	if p := e.Param(); p != "" {
		param = &p
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status())
	_ = json.NewEncoder(w).Encode(ErrorEnvelope{Error: ErrorObject{
		Type:     errorType(e.Status()),
		Code:     e.Code(),
		Message:  e.Message(),
		Param:    param,
		Metadata: e.Metadata(),
	}})
}

func errorType(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return "authentication_error"
	case status == http.StatusForbidden:
		return "authorization_error"
	case status == http.StatusTooManyRequests:
		return "rate_limit_error"
	case status >= 500:
		return "api_error"
	}
	return "invalid_request_error"
}
