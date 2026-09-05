// Package errmodel is the one error model every AuthKit package speaks
// (ak#290): a Code, an Error carrying that code plus its HTTP status, an
// optional offending param, machine metadata and a cause, and the catalog
// that fixes each code's status and message. It sits below the root package
// so documents (which root imports) can define its codes on the same model.
package errmodel

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

type entry struct {
	Status  int
	Param   string
	Message string
}

var catalog = map[Code]entry{}

// Define registers a code with its HTTP status and message and returns it.
// Package-level var initializers call it, so every code is in the catalog
// before any handler runs. Redefining a code is a programming error.
func Define(code string, status int, message string) Code {
	return DefineParam(code, status, "", message)
}

// DefineParam is Define for a validation code that always concerns one
// request field: the param is filled in when an Error carries none.
func DefineParam(code string, status int, param, message string) Code {
	c := Code(code)
	if _, dup := catalog[c]; dup {
		panic("authkit: error code defined twice: " + code)
	}
	catalog[c] = entry{Status: status, Param: param, Message: message}
	return c
}

// Describe reports a code's catalog status and message.
func Describe(code Code) (status int, message string, ok bool) {
	ent, ok := catalog[code]
	return ent.Status, ent.Message, ok
}

// DefaultParam is the catalog's field name for a validation code, if any.
func DefaultParam(code Code) string { return catalog[code].Param }

// Codes lists every catalogued code, sorted.
func Codes() []Code {
	out := make([]Code, 0, len(catalog))
	for c := range catalog {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Option customises an E() value.
type Option func(*Error)

// E builds an Error for a catalogued code (status from the catalog; an
// uncatalogued code is a 500).
func E(code Code, opts ...Option) *Error {
	e := &Error{Code: code, Status: http.StatusInternalServerError}
	if ent, ok := catalog[code]; ok {
		e.Status = ent.Status
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

func WithParam(param string) Option { return func(e *Error) { e.Param = param } }
func WithStatus(status int) Option  { return func(e *Error) { e.Status = status } }
func WithCause(cause error) Option  { return func(e *Error) { e.cause = cause } }
func WithMeta(key string, value any) Option {
	return func(e *Error) {
		if e.Meta == nil {
			e.Meta = map[string]any{}
		}
		e.Meta[key] = value
	}
}

// WithMetadata merges a whole map into Meta.
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

// Recode re-tags err with another code (a route-specific wire divergence),
// keeping err as the cause and carrying an inner Error's Param/Meta forward.
func Recode(err error, code Code, opts ...Option) *Error {
	e := E(code, WithCause(err))
	if inner := As(err); inner != nil {
		e.Param, e.Meta = inner.Param, inner.Meta
		if e.Param == "" {
			e.Param = DefaultParam(inner.Code)
		}
	}
	for _, o := range opts {
		o(e)
	}
	return e
}
