// Package authkitfiber bridges AuthKit's net/http middleware to Fiber v3.
// Build AuthKit's routes with authhttp.MountHandler and mount the result
// after host routes using Fallback. Verification policy stays in verify.
package authkitfiber

import (
	"net/http"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
)

// Fallback adapts authhttp.MountHandler to Fiber. Register it last with
// app.Use so host routes win and all AuthKit paths retain their full prefix.
func Fallback(h http.Handler) fiber.Handler {
	return func(c fiber.Ctx) error {
		r, err := adaptor.ConvertRequest(c, true)
		if err != nil {
			return fiber.ErrBadRequest
		}
		w := newResponseWriter(c)
		h.ServeHTTP(w, r.WithContext(c.Context()))
		w.flushHeaders()
		return nil
	}
}

// Required validates a credential and stores verified claims in c.Context().
// Like Gin's Required, it accepts every principal the verifier supports.
// A user-only handler must also check UserClaims.
func Required(v *verify.Verifier) fiber.Handler { return Use(verify.Required(v)) }

// Optional passes requests without Authorization through anonymously.
// A present but invalid credential is rejected, just as in verify.Optional.
func Optional(v *verify.Verifier) fiber.Handler { return Use(verify.Optional(v)) }

// RequiredLive adds an account-liveness check and fresh identity claims.
// It returns verify.ErrLivenessUnconfigured if no liveness source is wired.
func RequiredLive(v *verify.Verifier) (fiber.Handler, error) {
	mw, err := verify.RequiredLive(v)
	if err != nil {
		return nil, err
	}
	return Use(mw), nil
}

// Use runs synchronous net/http authentication middleware around Fiber's
// downstream handlers. Context values and cancellation flow in both directions;
// Fiber errors are returned to its error handler. Middleware must not retain the
// converted request after returning. Streaming and hijacking are not supported.
func Use(mw ...func(http.Handler) http.Handler) fiber.Handler {
	return func(c fiber.Ctx) error {
		r, err := adaptor.ConvertRequest(c, true)
		if err != nil {
			return fiber.ErrBadRequest
		}
		w := newResponseWriter(c)
		var nextErr error
		var h http.Handler = http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			c.SetContext(r.Context())
			w.flushHeaders()
			nextErr = c.Next()
			// Fiber writes its response directly. A middleware write after Next
			// must append to that response rather than reset its status.
			w.wroteHeader = true
		})
		for i := len(mw) - 1; i >= 0; i-- {
			if mw[i] != nil {
				h = mw[i](h)
			}
		}
		h.ServeHTTP(w, r.WithContext(c.Context()))
		w.flushHeaders()
		return nextErr
	}
}

// Claims returns the claims verified by authentication middleware.
func Claims(c fiber.Ctx) (verify.Claims, bool) {
	if c == nil {
		return verify.Claims{}, false
	}
	return verify.ClaimsFromContext(c.Context())
}

// Principal returns the typed user, API-key, or application principal.
func Principal(c fiber.Ctx) (authkit.Principal, bool) {
	cl, ok := Claims(c)
	if !ok {
		return authkit.Principal{}, false
	}
	p := cl.Principal()
	return p, p.Kind != ""
}

// UserClaimsData matches the Gin adapter's local-user projection.
type UserClaimsData struct {
	UserID        string
	Email         string
	EmailVerified bool
	Username      string
	SessionID     string
	Entitlements  []string
	AMR           []string
	ACR           string
	AuthTime      time.Time
	MFAEnrolled   bool
}

// UserClaims returns only a verified local user, never a machine principal or
// an external issuer's subject. Returned slices are copies, like the Gin helper.
func UserClaims(c fiber.Ctx) (UserClaimsData, bool) {
	cl, ok := Claims(c)
	if !ok || !cl.IsUser() {
		return UserClaimsData{}, false
	}
	return UserClaimsData{
		UserID: cl.UserID, Email: cl.Email, EmailVerified: cl.EmailVerified,
		Username: cl.Username, SessionID: cl.SessionID,
		Entitlements: append([]string(nil), cl.Entitlements...),
		AMR:          append([]string(nil), cl.AMR...), ACR: cl.ACR,
		AuthTime: cl.AuthTime, MFAEnrolled: cl.MFAEnrolled,
	}, true
}

// RequirePermission checks the canonical permission policy using a
// Fiber-native scope resolver. Mount after Required or RequiredLive.
func RequirePermission(checker verify.PermissionChecker, perm authkit.Perm, resolve func(fiber.Ctx) verify.PermissionScope) fiber.Handler {
	return func(c fiber.Ctx) error {
		var resolver func(*http.Request) verify.PermissionScope
		if resolve != nil {
			resolver = func(*http.Request) verify.PermissionScope { return resolve(c) }
		}
		return Use(verify.RequirePermission(checker, perm, resolver))(c)
	}
}

// responseWriter writes directly into Fiber's response, so a downstream Fiber
// handler's body and status are never overwritten by a buffered HTTP adapter.
type responseWriter struct {
	c           fiber.Ctx
	header      http.Header
	wroteHeader bool
}

func newResponseWriter(c fiber.Ctx) *responseWriter {
	return &responseWriter{c: c, header: make(http.Header)}
}

func (w *responseWriter) Header() http.Header { return w.header }

func (w *responseWriter) flushHeaders() {
	if w.wroteHeader {
		return
	}
	for key, values := range w.header {
		w.c.Response().Header.Del(key)
		for _, value := range values {
			w.c.Response().Header.Add(key, value)
		}
	}
}

func (w *responseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.flushHeaders()
	w.c.Status(status)
	if status >= 200 {
		w.wroteHeader = true
	}
}

func (w *responseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		if w.header.Get("Content-Type") == "" {
			w.header.Set("Content-Type", http.DetectContentType(body))
		}
		w.WriteHeader(http.StatusOK)
	}
	w.c.Response().AppendBody(body)
	return len(body), nil
}
