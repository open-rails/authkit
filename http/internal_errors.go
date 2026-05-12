package authhttp

import (
	"context"
	"fmt"
	"net/http"
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
