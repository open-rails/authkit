package authhttp

import (
	"context"
	"log/slog"
	"net/http"
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
