package authhttp

import (
	"context"
	"fmt"
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
		slog.String("path", logText(path)),
		slog.String("error", logText(err.Error())),
	)
}

// logText escapes control characters in request-derived text so a crafted
// path (e.g. %0A) cannot forge extra log lines whatever handler the host
// installed (CWE-117).
func logText(s string) string {
	q := fmt.Sprintf("%q", s)
	return q[1 : len(q)-1]
}
