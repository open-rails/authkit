package errmodel

import (
	"encoding/json"
	"time"

	"github.com/open-rails/authkit/internal/wireform"
)

// Error metadata is typed per code: each code that carries metadata has one
// shape (httpapi.ErrorMetadata lists them for the contract), set with
// WithDetails. The shapes the lowest layers produce live here.

// WithDetails sets the metadata from v, a struct marshaled in wire form as a
// JSON object.
func WithDetails(v any) Option {
	raw, err := json.Marshal(wireform.Of(v))
	var meta map[string]any
	if err == nil {
		err = json.Unmarshal(raw, &meta)
	}
	if err != nil {
		panic("errmodel: details must marshal to a JSON object: " + err.Error())
	}
	return WithMetadata(meta)
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
