package authhttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

// logInternalError records a swallowed internal handler error to the
// host-controlled slog default (#143: no public error-logger hook). Details stay
// server-side — clients only ever see the generic error envelope.
func (s *Service) logInternalError(r *http.Request, route, stage, code string, err error) {
	if err == nil {
		return
	}
	ctx := context.Background()
	method := ""
	path := ""
	if r != nil {
		ctx = r.Context()
		method = r.Method
		if r.URL != nil {
			path = r.URL.Path
		}
	}
	slog.Default().ErrorContext(ctx, "authkit: internal handler error",
		slog.String("route", route),
		slog.String("stage", stage),
		slog.String("code", code),
		slog.String("method", method),
		slog.String("path", path),
		slog.String("error", err.Error()),
	)
}

func (s *Service) handleDeliveryError(w http.ResponseWriter, r *http.Request, route, stage string, err error) bool {
	code := deliveryErrCode(err)
	if code == "" {
		return false
	}
	s.logInternalError(r, route, stage, code.String(), err)
	deliveryErr(w, code)
	return true
}

func handleVerificationRequestError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
		badRequest(w, code)
		return true
	}
	switch {
	case errors.Is(err, authkit.ErrUserNotFound):
		notFound(w, ErrUserNotFound)
		return true
	case errors.Is(err, authkit.ErrPendingRegistrationNotFound):
		notFound(w, ErrPendingRegistrationNotFound)
		return true
	case errors.Is(err, authkit.ErrEmailAlreadyVerified):
		sendErr(w, http.StatusConflict, ErrEmailAlreadyVerified)
		return true
	case errors.Is(err, authkit.ErrPhoneAlreadyVerified):
		sendErr(w, http.StatusConflict, ErrPhoneAlreadyVerified)
		return true
	case errors.Is(err, authkit.ErrVerificationLinkExpired):
		sendErr(w, http.StatusGone, ErrVerificationLinkExpired)
		return true
	default:
		return false
	}
}
