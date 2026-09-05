package authhttp

import (
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	authkit "github.com/open-rails/authkit"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError is the ONE error writer (ak#290): err goes through
// authkit.WriteError, which takes status, code, param and metadata from the
// error itself and collapses every 500 to internal_error on the wire. A 5xx
// is logged with its real code and cause, which is where the operation name
// lives now.
func writeError(w http.ResponseWriter, err error) {
	if status, _ := authkit.ErrorEnvelopeFor(err); status >= 500 {
		slog.Default().Error("authkit: request failed", slog.Int("status", status), slog.String("error", errorString(err)))
	}
	authkit.WriteError(w, err)
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// remap re-tags err with a route-specific wire code when it matches one of the
// listed identities; every other error passes through to the catalog.
func remap(err error, maps ...map[error]authkit.Code) error {
	for _, m := range maps {
		for target, code := range m {
			if errors.Is(err, target) {
				return authkit.Recode(err, code)
			}
		}
	}
	return err
}

// fallback re-tags anything the catalog would answer as a 5xx with a
// route-level code, for paths that must not leak a server failure.
func fallback(err error, code authkit.Code) error {
	if e := authkit.AsError(err); e != nil && e.Status < 500 {
		return err
	}
	return authkit.Recode(err, code)
}

// wireCode is the status and code writeError would put on the wire for err.
func wireCode(err error) (int, authkit.Code) {
	status, env := authkit.ErrorEnvelopeFor(err)
	return status, authkit.Code(env.Error.Code)
}

// notFoundCodes: the resource-not-found family answers one generic not_found.
var notFoundCodes = map[error]authkit.Code{
	authkit.ErrGroupNotFound:                 authkit.CodeNotFound,
	authkit.ErrRemoteApplicationNotFound:     authkit.CodeNotFound,
	authkit.ErrInviteLinkNotFound:            authkit.CodeNotFound,
	authkit.ErrGroupMembershipInviteNotFound: authkit.CodeNotFound,
	authkit.ErrPasskeyNotFound:               authkit.CodeNotFound,
}

func sendErr(w http.ResponseWriter, status int, code authkit.Code) {
	writeError(w, authkit.E(code, authkit.WithStatus(status)))
}

// sendErrData attaches machine-readable context under error.metadata.
func sendErrData(w http.ResponseWriter, status int, code authkit.Code, data map[string]any) {
	writeError(w, authkit.E(code, authkit.WithStatus(status), authkit.WithMetadata(data)))
}

// badRequestParam emits a 400 naming the offending request field in error.param.
func badRequestParam(w http.ResponseWriter, code authkit.Code, param string) {
	writeError(w, authkit.E(code, authkit.WithStatus(http.StatusBadRequest), authkit.WithParam(param)))
}

// badRequest emits a 400; a validation code carries its catalogued param.
func badRequest(w http.ResponseWriter, code authkit.Code) { sendErr(w, http.StatusBadRequest, code) }
func unauthorized(w http.ResponseWriter, code authkit.Code) {
	sendErr(w, http.StatusUnauthorized, code)
}
func forbidden(w http.ResponseWriter, code authkit.Code) { sendErr(w, http.StatusForbidden, code) }
func notFound(w http.ResponseWriter, code authkit.Code)  { sendErr(w, http.StatusNotFound, code) }

// serverErr emits a 500: on the wire always internal_error, in the log the
// code names the failed operation.
func serverErr(w http.ResponseWriter, code authkit.Code) {
	sendErr(w, http.StatusInternalServerError, code)
}

// registrationDisabled writes the stable registration-disabled rejection used by
// every public user-creation path when NativeUserRegistrationMode is set.
func registrationDisabled(w http.ResponseWriter) {
	sendErr(w, http.StatusForbidden, authkit.CodeRegistrationDisabled)
}

func tooMany(w http.ResponseWriter, retryAfter ...time.Duration) {
	if len(retryAfter) == 0 || retryAfter[0] <= 0 {
		sendErr(w, http.StatusTooManyRequests, authkit.CodeRateLimited)
		return
	}
	seconds := int(math.Ceil(retryAfter[0].Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	sendErrData(w, http.StatusTooManyRequests, authkit.CodeRateLimited, map[string]any{"retry_after_seconds": seconds})
}

func tooManyAvailability(w http.ResponseWriter, availability ActionAvailability, legacyError authkit.Code) {
	if legacyError == "" {
		legacyError = authkit.CodeRateLimited
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
	sendErrData(w, http.StatusTooManyRequests, legacyError, availabilityMap(availability))
}

func availabilityMap(a ActionAvailability) map[string]any {
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

// noContent is the ack for a mutation with nothing to return (#313).
func noContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// accepted is the empty-bodied ack for anti-enumeration sends and other
// deferred work (#313).
func accepted(w http.ResponseWriter) { w.WriteHeader(http.StatusAccepted) }

// writeList answers the one list envelope: {object:"list", data, next_cursor?}.
func writeList[T any](w http.ResponseWriter, items []T, nextCursor string) {
	writeJSON(w, http.StatusOK, authkit.NewListPage(items, nextCursor))
}
