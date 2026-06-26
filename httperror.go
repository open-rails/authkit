package authkit

import "strings"

// Stripe-style HTTP error envelope, shared by authhttp and the core-free verify
// package so both surfaces emit an identical shape. Structurally identical to
// openrails' pkg/api.ErrorResponse (the ecosystem-wide error contract): the
// machine-readable `code` is stable, `type` categorizes it, `message` is human
// readable, and `param`/`metadata` carry optional context.
//
// authkit is the LOWER layer (openrails imports authkit, not vice versa), so the
// canonical definition lives here.

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
	case 401:
		return ErrorTypeAuthentication
	case 403:
		return ErrorTypeAuthorization
	case 429:
		return ErrorTypeRateLimit
	}
	if status >= 500 {
		return ErrorTypeAPI
	}
	return ErrorTypeInvalidRequest // 400/404/409 and other 4xx
}

// NewErrorEnvelope builds the canonical nested error envelope for an HTTP status
// + machine code: the type is derived from the status and the message from the
// code catalog. param and metadata are optional (omitted when nil/empty).
func NewErrorEnvelope(status int, code string, param *string, metadata map[string]any) ErrorEnvelope {
	if len(metadata) == 0 {
		metadata = nil
	}
	return ErrorEnvelope{Error: ErrorObject{
		Type:     ErrorTypeForStatus(status),
		Code:     code,
		Message:  ErrorMessage(code),
		Param:    param,
		Metadata: metadata,
	}}
}

// ErrorMessage returns a human-readable English message for a wire error code:
// a curated message for common codes, otherwise a humanized form of the code so
// the message is never empty. Localized catalogs are a future extension.
func ErrorMessage(code string) string {
	if m, ok := errorMessages[code]; ok {
		return m
	}
	return humanizeCode(code)
}

// errorMessages curates the most common / user-facing codes; every other code
// falls back to humanizeCode. Keys are wire-code VALUES (see authhttp error
// constants); a missing or mismatched key is harmless (humanized fallback).
var errorMessages = map[string]string{
	"invalid_request":         "The request is invalid.",
	"validation_failed":       "One or more fields are invalid.",
	"not_found":               "The requested resource was not found.",
	"duplicate_resource":      "That resource already exists.",
	"authentication_required": "Authentication is required.",
	"authentication_failed":   "Authentication failed.",
	"not_authenticated":       "Authentication is required.",
	"invalid_token":           "The authentication token is invalid.",
	"token_expired":           "The authentication token has expired.",
	"forbidden":               "You do not have permission to perform this action.",
	"step_up_required":        "Additional verification is required to continue.",
	"rate_limited":            "Too many requests. Please try again later.",
	"registration_disabled":   "Registration is currently disabled.",
	"password_reset_required": "A password reset is required before you can sign in.",
	"database_error":          "An internal error occurred. Please try again.",
	"internal_error":          "An internal error occurred. Please try again.",
}

// acronyms are uppercased whole when they appear as a code segment, so humanized
// messages read naturally (e.g. "2fa_send_failed" -> "2FA send failed.").
var acronyms = map[string]string{
	"2fa": "2FA", "oidc": "OIDC", "siws": "SIWS", "api": "API", "sms": "SMS",
	"url": "URL", "id": "ID", "jwt": "JWT", "ttl": "TTL", "ip": "IP",
	"otp": "OTP", "rbac": "RBAC", "totp": "TOTP", "sns": "SNS",
}

// humanizeCode turns a snake_case wire code into a sentence: segments joined by
// spaces, the first letter capitalized, known acronyms uppercased, terminated
// with a period.
func humanizeCode(code string) string {
	c := strings.TrimSpace(code)
	if c == "" {
		return "Request failed."
	}
	words := strings.Split(c, "_")
	for i, w := range words {
		if up, ok := acronyms[w]; ok {
			words[i] = up
			continue
		}
		if i == 0 && w != "" {
			r := []rune(w)
			if r[0] >= 'a' && r[0] <= 'z' {
				r[0] -= 'a' - 'A'
			}
			words[i] = string(r)
		}
	}
	s := strings.Join(words, " ")
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
