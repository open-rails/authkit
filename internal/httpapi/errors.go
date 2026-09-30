package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

// writeError writes err as the error envelope, status and code from the
// catalog. A server failure is logged with its op and cause; the wire only
// ever says internal_error.
func writeError(w http.ResponseWriter, err error) {
	if e := errmodel.Wire(err); e.Status() >= 500 {
		slog.Default().Error("authkit: request failed", slog.Int("status", e.Status()), slog.String("error", errorString(err)))
	}
	iam.WriteError(w, err)
}

// fail writes code with its catalog status.
func fail(w http.ResponseWriter, code errmodel.Code, opts ...errmodel.Option) {
	writeError(w, errmodel.E(code, opts...))
}

// serverErr writes 500 internal_error; op names the failed operation in the log.
func serverErr(w http.ResponseWriter, op string, cause error) {
	writeError(w, errmodel.Internal(op, cause))
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// remap re-tags err with a route-specific wire code when it matches one of the
// listed identities; every other error passes through to the catalog.
func remap(err error, maps ...map[error]errmodel.Code) error {
	for _, m := range maps {
		for target, code := range m {
			if errors.Is(err, target) {
				return errmodel.Recode(err, code)
			}
		}
	}
	return err
}

// fallback re-tags anything the catalog would answer as a 5xx with a
// route-level code, for paths that must not leak a server failure.
func fallback(err error, code errmodel.Code) error {
	if e := errmodel.As(err); e != nil && e.Status() < 500 {
		return err
	}
	return errmodel.Recode(err, code)
}

// codeRejection distinguishes a retryable wrong code from one with no live code.
func codeRejection(err error) errmodel.Code {
	if errors.Is(err, errmodel.ErrCodeExpired) {
		return errmodel.CodeCodeExpired
	}
	return errmodel.CodeInvalidCode
}

// registrationDisabled writes the stable registration-disabled rejection used by
// every public user-creation path when NativeUserRegistrationMode is set.
func registrationDisabled(w http.ResponseWriter) { fail(w, errmodel.CodeRegistrationDisabled) }

func tooMany(w http.ResponseWriter, retryAfter ...time.Duration) {
	if len(retryAfter) == 0 || retryAfter[0] <= 0 {
		fail(w, errmodel.CodeRateLimited)
		return
	}
	seconds := int(math.Ceil(retryAfter[0].Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	fail(w, errmodel.CodeRateLimited, errmodel.WithMetadata(map[string]any{"retry_after_seconds": seconds}))
}

func tooManyAvailability(w http.ResponseWriter, availability authflow.ActionAvailability) {
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
	fail(w, errmodel.CodeRateLimited, withDetails(availability))
}

// withDetails is an error's metadata from a typed value: its JSON object.
func withDetails(v any) errmodel.Option {
	raw, err := json.Marshal(wireForm(reflect.ValueOf(v)).Interface())
	var meta map[string]any
	if err == nil {
		err = json.Unmarshal(raw, &meta)
	}
	if err != nil {
		panic("httpapi: error details must marshal to a JSON object: " + err.Error())
	}
	return errmodel.WithMetadata(meta)
}

// noContent is the ack for a mutation with nothing to return (#313).
func noContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// accepted is the empty-bodied ack for anti-enumeration sends and other
// deferred work (#313).
func accepted(w http.ResponseWriter) { w.WriteHeader(http.StatusAccepted) }
