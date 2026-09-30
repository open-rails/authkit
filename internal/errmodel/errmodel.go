// Package errmodel is AuthKit's one error model: the catalog fixing every wire
// code's HTTP status and message, the concrete error value, and its
// constructors. Hosts see these values only through iam.Error.
package errmodel

//go:generate go run ../cmd/contract -out ../../auth-ui/src/client/generated

import (
	"errors"
	"maps"
	"net/http"
	"sort"
)

// Code is a stable, snake_case wire error code.
type Code string

func (c Code) String() string { return string(c) }

// Error is the one error value. Its status is always the catalog's for its
// code: no call site can override it. An uncatalogued code, and every
// Internal failure, answers 500 internal_error on the wire.
type Error struct {
	code  Code
	op    string // Internal failures: the failed operation, logged only
	param string
	meta  map[string]any
	cause error
}

func (e *Error) Error() string {
	label := string(e.code)
	if e.op != "" {
		label = e.op
	}
	if e.cause != nil {
		return label + ": " + e.cause.Error()
	}
	return label
}

func (e *Error) Unwrap() error { return e.cause }

// Is matches any *Error with the same code (and, for Internal failures, the
// same op), so a sentinel, a fresh E() and a wrapped copy are one identity.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.code == e.code && t.op == e.op
}

// Code is the wire code: the catalog code, or internal_error for a 500.
func (e *Error) Code() string {
	if e.Status() == http.StatusInternalServerError {
		return string(CodeInternalError)
	}
	return string(e.code)
}

// Status is the catalog's HTTP status for the code (500 when uncatalogued).
func (e *Error) Status() int {
	if ent, ok := catalog[e.code]; ok {
		return ent.status
	}
	return http.StatusInternalServerError
}

// Param names the offending request field: the site's, else the catalog's.
// A server failure carries none.
func (e *Error) Param() string {
	switch {
	case e.Status() == http.StatusInternalServerError:
		return ""
	case e.param != "":
		return e.param
	}
	return catalog[e.code].param
}

// Metadata is a copy of the machine-readable context (nil when empty or for a
// server failure).
func (e *Error) Metadata() map[string]any {
	if len(e.meta) == 0 || e.Status() == http.StatusInternalServerError {
		return nil
	}
	return maps.Clone(e.meta)
}

// Message is the catalog's human-readable message for the wire code.
func (e *Error) Message() string { return Message(Code(e.Code())) }

type entry struct {
	status  int
	param   string
	message string
}

var catalog = map[Code]entry{}

// def registers a wire code. Package-level initializers call it, so every code
// is catalogued before any handler runs. A 500 is not a wire code (use
// Internal), and redefining a code is a programming error.
func def(code string, status int, message string) Code {
	return defParam(code, status, "", message)
}

// defParam is def for a validation code that always concerns one request field.
func defParam(code string, status int, param, message string) Code {
	c := Code(code)
	if _, dup := catalog[c]; dup {
		panic("errmodel: code defined twice: " + code)
	}
	if status == http.StatusInternalServerError && code != "internal_error" {
		panic("errmodel: a 500 is not a wire code, use Internal: " + code)
	}
	catalog[c] = entry{status: status, param: param, message: message}
	return c
}

// Codes lists every wire code, sorted.
func Codes() []Code {
	out := make([]Code, 0, len(catalog))
	for c := range catalog {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Status is the catalog status of code (500 when uncatalogued).
func Status(code Code) int { return (&Error{code: code}).Status() }

// Message is the catalog message of code.
func Message(code Code) string {
	if ent, ok := catalog[code]; ok {
		return ent.message
	}
	return "Request failed."
}

// Option customises an E() value.
type Option func(*Error)

// E builds an Error for a catalogued code.
func E(code Code, opts ...Option) *Error {
	e := &Error{code: code}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Internal is a server failure: internal_error on the wire, op and cause in
// the log.
func Internal(op string, cause error) *Error {
	return &Error{code: CodeInternalError, op: op, cause: cause}
}

func WithParam(param string) Option { return func(e *Error) { e.param = param } }
func WithCause(cause error) Option  { return func(e *Error) { e.cause = cause } }
func WithMeta(key string, value any) Option {
	return func(e *Error) {
		if e.meta == nil {
			e.meta = map[string]any{}
		}
		e.meta[key] = value
	}
}

// WithMetadata merges a whole map into the metadata.
func WithMetadata(m map[string]any) Option {
	return func(e *Error) {
		for k, v := range m {
			WithMeta(k, v)(e)
		}
	}
}

// As returns the *Error in err's chain, or nil.
func As(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

// CodeOf is the catalog code of the *Error in err's chain ("" when none).
func CodeOf(err error) Code {
	if e := As(err); e != nil {
		return e.code
	}
	return ""
}

// Recode re-tags err with a route-specific code, keeping err as the cause and
// carrying an inner Error's param and metadata forward.
func Recode(err error, code Code, opts ...Option) *Error {
	e := E(code, WithCause(err))
	if inner := As(err); inner != nil {
		e.param, e.meta = inner.Param(), inner.meta
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Wire is what the envelope carries for err: anything that is not an *Error
// is a 500 internal_error.
func Wire(err error) *Error {
	if e := As(err); e != nil {
		return e
	}
	return Internal("", err)
}
