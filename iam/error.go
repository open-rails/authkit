package iam

// The one error model (ak#290): a Code, an Error carrying code + HTTP status +
// param + metadata + cause, and ONE catalog fixing every code's status and
// message. The engine, documents, verify and the HTTP layer all return
// E(CodeX) and write the wire envelope with WriteError. Every 500 collapses to
// internal_error on the wire (the specific code stays in the log).

import (
	"errors"
	"net/http"
	"sort"
)

// Code is a stable, snake_case wire error code.
type Code string

func (c Code) String() string { return string(c) }

// Error is the one error value: Code identifies it (errors.Is compares codes),
// Status is the HTTP status the catalog fixed for the code (an explicit
// WithStatus overrides it per site), Param names the offending request field,
// Meta carries machine-readable context, and the cause is the wrapped error.
type Error struct {
	Code   Code
	Status int
	Param  string
	Meta   map[string]any
	cause  error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return string(e.Code) + ": " + e.cause.Error()
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error { return e.cause }

// Is matches any *Error with the same Code, so a sentinel var, a fresh E() and
// a wrapped copy are all one identity.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// Message is the catalog's human-readable message for the code.
func (e *Error) Message() string {
	if ent, ok := catalog[e.Code]; ok {
		return ent.Message
	}
	return "Request failed."
}

type catalogEntry struct {
	Status  int
	Param   string
	Message string
}

var catalog = map[Code]catalogEntry{}

// def registers a code with its HTTP status and message. Package-level var
// initializers call it, so every code is in the catalog before any handler
// runs. Redefining a code is a programming error.
func def(code string, status int, message string) Code {
	return defParam(code, status, "", message)
}

// defParam is def for a validation code that always concerns one request
// field: the param is filled in when an Error carries none.
func defParam(code string, status int, param, message string) Code {
	c := Code(code)
	if _, dup := catalog[c]; dup {
		panic("authkit: error code defined twice: " + code)
	}
	catalog[c] = catalogEntry{Status: status, Param: param, Message: message}
	return c
}

// DescribeCode reports a code's catalog status and message.
func DescribeCode(code Code) (status int, message string, ok bool) {
	ent, ok := catalog[code]
	return ent.Status, ent.Message, ok
}

func defaultParam(code Code) string { return catalog[code].Param }

// Codes lists every catalogued code, sorted.
func Codes() []Code {
	out := make([]Code, 0, len(catalog))
	for c := range catalog {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ErrorOption customises an E() value.
type ErrorOption func(*Error)

// E builds an Error for a catalogued code (status from the catalog; an
// uncatalogued code is a 500).
func E(code Code, opts ...ErrorOption) *Error {
	e := &Error{Code: code, Status: http.StatusInternalServerError}
	if ent, ok := catalog[code]; ok {
		e.Status = ent.Status
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

func WithParam(param string) ErrorOption { return func(e *Error) { e.Param = param } }
func WithStatus(status int) ErrorOption  { return func(e *Error) { e.Status = status } }
func WithCause(cause error) ErrorOption  { return func(e *Error) { e.cause = cause } }
func WithMeta(key string, value any) ErrorOption {
	return func(e *Error) {
		if e.Meta == nil {
			e.Meta = map[string]any{}
		}
		e.Meta[key] = value
	}
}

// WithMetadata merges a whole map into Meta.
func WithMetadata(m map[string]any) ErrorOption {
	return func(e *Error) {
		for k, v := range m {
			WithMeta(k, v)(e)
		}
	}
}

// AsError returns the *Error in err's chain, or nil.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

// Recode re-tags err with a route-specific code, keeping err as the cause and
// carrying an inner Error's Param/Meta forward.
func Recode(err error, code Code, opts ...ErrorOption) *Error {
	e := E(code, WithCause(err))
	if inner := AsError(err); inner != nil {
		e.Param, e.Meta = inner.Param, inner.Meta
		if e.Param == "" {
			e.Param = defaultParam(inner.Code)
		}
	}
	for _, o := range opts {
		o(e)
	}
	return e
}
