package errmodel

import (
	"reflect"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/wireform"
)

// Error metadata is typed per code: each code that carries metadata has one
// shape (httpapi.ErrorMetadata lists them for the contract), set with
// WithDetails. The shapes the lowest layers produce live here.

// WithDetails sets the metadata from v, a struct: one member per json-tagged
// field, in wire form, keeping its Go type for Go callers of Metadata.
func WithDetails(v any) Option {
	rv := reflect.ValueOf(wireform.Of(v))
	if rv.Kind() != reflect.Struct {
		panic("errmodel: details must be a struct, got " + rv.Kind().String())
	}
	meta := map[string]any{}
	t := rv.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		meta[name] = rv.Field(i).Interface()
	}
	return func(e *Error) { e.meta = meta }
}

// ActionAvailability says whether a limited action is allowed now, and when
// it will be: the metadata of rate_limited and rename_rate_limited.
type ActionAvailability struct {
	Action            string     `json:"action"`
	Allowed           bool       `json:"allowed"`
	Reason            string     `json:"reason"`
	RetryAfterSeconds int64      `json:"retry_after_seconds"`
	NextAllowedAt     *time.Time `json:"next_allowed_at"`
	Limit             *int       `json:"limit"`
	Remaining         *int       `json:"remaining"`
	WindowSeconds     *int64     `json:"window_seconds"`
	CooldownSeconds   *int64     `json:"cooldown_seconds"`
}

// RetryAfter is server_busy's metadata: when to try again (also the
// Retry-After header).
type RetryAfter struct {
	RetryAfterSeconds int64 `json:"retry_after_seconds"`
}

// LengthBounds is a length rule a value broke: the metadata of
// username_too_short/long and password_too_short/long.
type LengthBounds struct {
	MinLength int `json:"min_length"`
	MaxLength int `json:"max_length"`
}

// PasswordRequirements lists the character classes a new password lacks:
// the metadata of password_requirements_unmet.
type PasswordRequirements struct {
	Missing []string `json:"missing"`
}

// ContactProofRequired names the address an account must prove first: the
// metadata of verification_required and contact_not_verified. Reason says why
// ("contact_unproven" when no address is proven yet).
type ContactProofRequired struct {
	Identifier string `json:"identifier"`
	Channel    string `json:"channel"`
	Reason     string `json:"reason"`
}
