package authhttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	core "github.com/open-rails/authkit/core"
)

// InternalErrorEvent captures a swallowed internal handler error so host apps
// can log it without exposing implementation details to clients.
type InternalErrorEvent struct {
	Route  string
	Stage  string
	Code   string
	Method string
	Path   string
	Err    error
}

func (e InternalErrorEvent) Error() string {
	return fmt.Sprintf("route=%s stage=%s code=%s method=%s path=%s: %v", e.Route, e.Stage, e.Code, e.Method, e.Path, e.Err)
}

func (s *Service) logInternalError(r *http.Request, route, stage, code string, err error) {
	if s == nil || s.errorLogger == nil || err == nil {
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
	s.errorLogger(ctx, InternalErrorEvent{
		Route:  route,
		Stage:  stage,
		Code:   code,
		Method: method,
		Path:   path,
		Err:    err,
	})
}

func (s *Service) handleDeliveryError(w http.ResponseWriter, r *http.Request, route, stage string, err error) bool {
	code := deliveryErrCode(err)
	if code == "" {
		return false
	}
	s.logInternalError(r, route, stage, code, err)
	deliveryErr(w, code)
	return true
}

func handleVerificationRequestError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if code := core.ValidationErrorCode(err); code != "" {
		badRequest(w, code)
		return true
	}
	switch {
	case errors.Is(err, core.ErrUserNotFound):
		notFound(w, "user_not_found")
		return true
	case errors.Is(err, core.ErrPendingRegistrationNotFound):
		notFound(w, "pending_registration_not_found")
		return true
	case errors.Is(err, core.ErrEmailAlreadyVerified):
		sendErr(w, http.StatusConflict, "email_already_verified")
		return true
	case errors.Is(err, core.ErrPhoneAlreadyVerified):
		sendErr(w, http.StatusConflict, "phone_already_verified")
		return true
	default:
		return false
	}
}
