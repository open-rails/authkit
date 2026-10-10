package iam

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"strconv"

	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/helpers/auth"
)

// ErrorObject is the error detail under the envelope's "error" key: a stable
// code, its type category (derived from the status), a human-readable
// message, the offending request field (null for none) and machine-readable
// metadata (null for none).
type ErrorObject struct {
	Type     string         `json:"type"`
	Code     string         `json:"code"`
	Message  string         `json:"message"`
	Param    *string        `json:"param"`
	Metadata map[string]any `json:"metadata"`
}

// ErrorEnvelope is every AuthKit error response: {"error": {...}}.
type ErrorEnvelope struct {
	Error ErrorObject `json:"error"`
}

// WriteError writes err as the error envelope with the catalog's status for
// its code. Anything that is not an AuthKit error, and every server failure,
// is written as 500 internal_error. A 401 step_up_required also carries RFC
// 9470's challenge, `Bearer error="insufficient_user_authentication",
// max_age="900"`, unless the response already has a WWW-Authenticate.
func WriteError(w http.ResponseWriter, err error) {
	status, body := ErrorResponse(err)
	if maxAge, _, ok := errmodel.StepUp(err); ok && w.Header().Get("WWW-Authenticate") == "" {
		challenge := &auth.Challenge{Err: auth.ErrStepUpRequired, MaxAge: maxAge}
		w.Header().Set("WWW-Authenticate", auth.Refuse(nil, challenge).Header.Get("WWW-Authenticate"))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ErrorResponse is WriteError's status and envelope, for any router:
// Gin `c.JSON(iam.ErrorResponse(err))`, Fiber `status, body :=
// iam.ErrorResponse(err); return c.Status(status).JSON(body)`.
func ErrorResponse(err error) (int, ErrorEnvelope) {
	e := errmodel.Wire(err)
	var param *string
	if p := e.Param(); p != "" {
		param = &p
	}
	return e.Status(), ErrorEnvelope{Error: ErrorObject{
		Type:     errorType(e.Status()),
		Code:     e.Code(),
		Message:  e.Message(),
		Param:    param,
		Metadata: e.Metadata(),
	}}
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

// maxErrorBody bounds the error body DecodeError reads.
const maxErrorBody = 64 << 10

// DecodeError is WriteError's inverse for an HTTP client of AuthKit: nil for a
// 2xx response, else the Error the response carries, with the response's
// status and the envelope's code, message, param and metadata. errors.Is
// matches it against the Err* sentinels by code. A body that is not an
// AuthKit envelope (a proxy's error page, an unmounted route) decodes to an
// Error with the status and an empty code. DecodeError reads the body but
// does not close it.
func DecodeError(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	e := &responseError{status: resp.StatusCode}
	if resp.Body != nil {
		var env ErrorEnvelope
		if raw, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody)); err == nil && json.Unmarshal(raw, &env) == nil {
			e.obj = env.Error
		}
	}
	return e
}

// responseError is an Error decoded from an HTTP response.
type responseError struct {
	status int
	obj    ErrorObject
}

func (e *responseError) Error() string {
	switch {
	case e.obj.Code == "":
		return "authkit: HTTP " + strconv.Itoa(e.status)
	case e.obj.Message == "":
		return e.obj.Code
	}
	return e.obj.Code + ": " + e.obj.Message
}

func (e *responseError) Code() string { return e.obj.Code }
func (e *responseError) Status() int  { return e.status }

func (e *responseError) Param() string {
	if e.obj.Param == nil {
		return ""
	}
	return *e.obj.Param
}

func (e *responseError) Metadata() map[string]any { return maps.Clone(e.obj.Metadata) }

// Is matches a sentinel with the same wire code. internal_error matches
// none: the wire does not say which failure it was.
func (e *responseError) Is(target error) bool {
	t, ok := target.(*errmodel.Error)
	return ok && e.obj.Code != "" && e.obj.Code != string(errmodel.CodeInternalError) && t.Code() == e.obj.Code
}
