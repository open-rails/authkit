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

// SignInLimit is the metadata of too_many_accounts and too_many_devices: the
// limit reached, and when the oldest sign-in counted leaves the 24 hours
// (also the Retry-After header).
type SignInLimit struct {
	Limit             int   `json:"limit"`
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

// AgreementsRequired is agreement_required's metadata: the documents, at
// their current versions, still to accept.
type AgreementsRequired struct {
	Agreements []AgreementDocument `json:"agreements"`
}

// AgreementDocument is one document at one version.
type AgreementDocument struct {
	Key     string `json:"key"`
	Version string `json:"version"`
	URL     string `json:"url"`
}

// Refusal is the metadata of a refusal a host hook gave (deletion_refused,
// consent_revocation_refused): its reason code.
type Refusal struct {
	Reason string `json:"reason"`
}

// PhoneCountry is phone_country_not_allowed's metadata: the number's region
// (ISO 3166-1 alpha-2; empty when unknown).
type PhoneCountry struct {
	Country string `json:"country"`
}

// ConsentRequired is consent_required's metadata: the scopes, with what
// each allows, the user has yet to consent to.
type ConsentRequired struct {
	Scopes []ScopeDescription `json:"scopes"`
}

// ScopeDescription is one OAuth scope and what consenting to it allows; ""
// for OpenID's own, which the interface describes.
type ScopeDescription struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}
