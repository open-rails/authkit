package authhttp

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	core "github.com/open-rails/authkit/core"
)

type errResp struct {
	Error ErrorCode `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func sendErr(w http.ResponseWriter, status int, code ErrorCode) {
	writeJSON(w, status, errResp{Error: code})
}

func sendErrData(w http.ResponseWriter, status int, code ErrorCode, data map[string]any) {
	if data == nil {
		sendErr(w, status, code)
		return
	}
	data["error"] = code
	writeJSON(w, status, data)
}

func badRequest(w http.ResponseWriter, code ErrorCode)   { sendErr(w, http.StatusBadRequest, code) }
func unauthorized(w http.ResponseWriter, code ErrorCode) { sendErr(w, http.StatusUnauthorized, code) }
func forbidden(w http.ResponseWriter, code ErrorCode)    { sendErr(w, http.StatusForbidden, code) }

const (
	errRegistrationDisabled  = string(ErrRegistrationDisabled)
	errOrgManagementDisabled = string(ErrOrgManagementDisabled)
)

// registrationDisabled writes the stable registration-disabled rejection used by
// every public user-creation path when NativeUserRegistrationMode is set.
func registrationDisabled(w http.ResponseWriter) {
	sendErr(w, http.StatusForbidden, ErrRegistrationDisabled)
}

// orgManagementDisabled writes the stable org-management-disabled rejection used
// by public org onboarding/management routes when OrgRegistrationMode is
// set.
func orgManagementDisabled(w http.ResponseWriter) {
	sendErr(w, http.StatusForbidden, ErrOrgManagementDisabled)
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
	data := availability.toMap()
	data["error"] = legacyError
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
	writeJSON(w, http.StatusTooManyRequests, data)
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
