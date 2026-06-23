package authhttp

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/open-rails/authkit/authbase"
	core "github.com/open-rails/authkit/core"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// sendErr writes the canonical Stripe-style error envelope
// ({"error":{type,code,message}}); type is derived from the status and message
// from the code catalog (authbase). The shape is shared with the verify package.
func sendErr(w http.ResponseWriter, status int, code ErrorCode) {
	writeJSON(w, status, authbase.NewErrorEnvelope(status, string(code), nil, nil))
}

// sendErrData attaches machine-readable context under error.metadata (e.g.
// rate-limit/availability fields), keeping a single nested envelope shape.
func sendErrData(w http.ResponseWriter, status int, code ErrorCode, data map[string]any) {
	writeJSON(w, status, authbase.NewErrorEnvelope(status, string(code), nil, data))
}

// badRequestParam emits a 400 naming the offending request field in error.param.
func badRequestParam(w http.ResponseWriter, code ErrorCode, param string) {
	writeJSON(w, http.StatusBadRequest, authbase.NewErrorEnvelope(http.StatusBadRequest, string(code), &param, nil))
}

// validationParam maps a known identity-validation wire code to the request
// field it concerns, so a 400 for one of these codes carries error.param (#115).
// Any code not listed simply omits param.
var validationParam = map[ErrorCode]string{
	ErrorCode(core.ErrCodeUsernameTooShort):            "username",
	ErrorCode(core.ErrCodeUsernameTooLong):             "username",
	ErrorCode(core.ErrCodeUsernameMustStartWithLetter): "username",
	ErrorCode(core.ErrCodeUsernameCannotContainAt):     "username",
	ErrorCode(core.ErrCodeUsernameCannotStartWithPlus): "username",
	ErrorCode(core.ErrCodeUsernameInvalidCharacters):   "username",
	ErrorCode(core.ErrCodeUsernameNotAllowed):          "username",
	ErrorCode(core.ErrCodeOwnerSlugTaken):              "username",
	ErrorCode(core.ErrCodeInvalidEmail):                "email",
	ErrorCode(core.ErrCodeInvalidPhoneNumber):          "phone_number",
	ErrorCode(core.ErrCodePasswordTooShort):            "password",
}

// badRequest emits a 400. When the code is a known identity-validation code it
// also names the offending field in error.param (#115).
func badRequest(w http.ResponseWriter, code ErrorCode) {
	if p := validationParam[code]; p != "" {
		badRequestParam(w, code, p)
		return
	}
	sendErr(w, http.StatusBadRequest, code)
}
func unauthorized(w http.ResponseWriter, code ErrorCode) { sendErr(w, http.StatusUnauthorized, code) }
func forbidden(w http.ResponseWriter, code ErrorCode)    { sendErr(w, http.StatusForbidden, code) }

const (
	errRegistrationDisabled = string(ErrRegistrationDisabled)
)

// registrationDisabled writes the stable registration-disabled rejection used by
// every public user-creation path when NativeUserRegistrationMode is set.
func registrationDisabled(w http.ResponseWriter) {
	sendErr(w, http.StatusForbidden, ErrRegistrationDisabled)
}

func tooMany(w http.ResponseWriter, retryAfter ...time.Duration) {
	if len(retryAfter) == 0 || retryAfter[0] <= 0 {
		sendErr(w, http.StatusTooManyRequests, ErrRateLimited)
		return
	}
	seconds := int(math.Ceil(retryAfter[0].Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	sendErrData(w, http.StatusTooManyRequests, ErrRateLimited, map[string]any{"retry_after_seconds": seconds})
}

func tooManyAvailability(w http.ResponseWriter, availability ActionAvailability, legacyError ErrorCode) {
	if legacyError == "" {
		legacyError = ErrRateLimited
	}
	if availability.RetryAfterSeconds > 0 {
		seconds := int(availability.RetryAfterSeconds)
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		w.Header().Set("RateLimit-Reset", strconv.Itoa(seconds))
	}
	if availability.Limit != nil {
		w.Header().Set("RateLimit-Limit", strconv.Itoa(*availability.Limit))
	}
	if availability.Remaining != nil {
		w.Header().Set("RateLimit-Remaining", strconv.Itoa(*availability.Remaining))
	}
	sendErrData(w, http.StatusTooManyRequests, legacyError, availability.toMap())
}

func (a ActionAvailability) toMap() map[string]any {
	out := map[string]any{
		"action":  a.Action,
		"allowed": a.Allowed,
	}
	if a.Reason != "" {
		out["reason"] = a.Reason
	}
	if a.RetryAfterSeconds > 0 {
		out["retry_after_seconds"] = a.RetryAfterSeconds
	}
	if a.NextAllowedAt != nil {
		out["next_allowed_at"] = a.NextAllowedAt.Format(time.RFC3339)
	}
	if a.Limit != nil {
		out["limit"] = *a.Limit
	}
	if a.Remaining != nil {
		out["remaining"] = *a.Remaining
	}
	if a.WindowSeconds != nil {
		out["window_seconds"] = *a.WindowSeconds
	}
	if a.CooldownSeconds != nil {
		out["cooldown_seconds"] = *a.CooldownSeconds
	}
	return out
}
func serverErr(w http.ResponseWriter, code ErrorCode) {
	sendErr(w, http.StatusInternalServerError, code)
}
func notFound(w http.ResponseWriter, code ErrorCode) { sendErr(w, http.StatusNotFound, code) }
func deliveryErr(w http.ResponseWriter, code ErrorCode) {
	sendErr(w, http.StatusBadGateway, code)
}

func deliveryErrCode(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, core.ErrEmailDeliveryFailed):
		return ErrEmailDeliveryFailed
	case errors.Is(err, core.ErrSMSDeliveryFailed):
		return ErrSMSDeliveryFailed
	default:
		return ""
	}
}
