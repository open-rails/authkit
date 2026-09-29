// Package authkitfiber bridges AuthKit's net/http middleware to Fiber v3.
// Mount registers AuthKit's routes directly on the application. Verification
// policy stays in verify.
package authkitfiber

import (
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

func httpHandler(h http.Handler) fiber.Handler {
	return func(c fiber.Ctx) error {
		r, err := adaptor.ConvertRequest(c, true)
		if err != nil {
			return fiber.ErrBadRequest
		}
		// An implicit Fiber content type looks like an explicit host header to
		// net/http (and suppresses Redirect's HTML response). Let the canonical
		// handler choose its content type while retaining actual host headers.
		c.Response().Header.SetNoDefaultContentType(true)
		c.Status(http.StatusOK)
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

// OptionalLive admits anonymous requests and checks the liveness of presented
// native-user credentials. It returns verify.ErrLivenessUnconfigured at startup
// when no source is wired. Use on routes, groups, or as application middleware.
func OptionalLive(v *verify.Verifier) (fiber.Handler, error) {
	mw, err := verify.OptionalLive(v)
	if err != nil {
		return nil, err
	}
	return Use(mw), nil
}

// Use runs synchronous net/http authentication middleware around Fiber's
// downstream handlers. Context values and cancellation flow in both directions;
// Fiber errors are returned to its error handler. Middleware must not retain the
// converted request after returning. Streaming and hijacking are not supported.
// This bridge is for authentication and context middleware, not request
// rewriting or wrappers that intercept downstream response bodies.
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

// Identity returns the verified caller's provider-neutral identity (user,
// device key, API key, remote application or delegated principal).
func Identity(c fiber.Ctx) (auth.Identity, bool) {
	cl, ok := Claims(c)
	if !ok {
		return auth.Identity{}, false
	}
	return cl.Identity()
}

// Actor returns the actor the verified caller acts as, for passing to *authkit.Client
// operations. ok is false when the caller carries no AuthKit authority.
func Actor(c fiber.Ctx) (iam.Actor, bool) {
	if c == nil {
		return iam.Actor{}, false
	}
	return verify.ActorFromContext(c.Context())
}

// UserClaims returns only a verified local user, never a machine principal or
// an external issuer's subject. It performs no database lookup; profile
// availability depends on Required/Optional versus RequiredLive.
func UserClaims(c fiber.Ctx) (verify.UserClaimsData, bool) {
	if c == nil {
		return verify.UserClaimsData{}, false
	}
	return verify.UserClaimsFromContext(c.Context())
}

// RequirePermission authenticates the request (it includes Required) and
// requires perm, checked live, in the group resolve returns; a nil resolve
// means the root group. It panics at construction on a perm the authority
// does not register.
func RequirePermission(a verify.Authority, perm iam.Perm, resolve func(fiber.Ctx) iam.GroupRef) fiber.Handler {
	verify.MustKnowPermission(a, perm)
	return func(c fiber.Ctx) error {
		var r func(*http.Request) iam.GroupRef
		if resolve != nil {
			r = func(*http.Request) iam.GroupRef { return resolve(c) }
		}
		return Use(verify.RequirePermission(a, perm, r))(c)
	}
}

// responseWriter writes directly into Fiber's response, so a downstream Fiber
// handler's body and status are never overwritten by a buffered HTTP adapter.
type responseWriter struct {
	c            fiber.Ctx
	header       http.Header
	originalKeys []string
	wroteHeader  bool
}

func newResponseWriter(c fiber.Ctx) *responseWriter {
	w := &responseWriter{c: c, header: make(http.Header)}
	for key, value := range c.Response().Header.All() {
		name := string(key)
		w.header.Add(name, string(value))
		w.originalKeys = append(w.originalKeys, name)
	}
	return w
}

func (w *responseWriter) Header() http.Header { return w.header }

func (w *responseWriter) flushHeaders() {
	if w.wroteHeader {
		return
	}
	for _, key := range w.originalKeys {
		w.c.Response().Header.Del(key)
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
	// net/http sniffs the first nonempty body even after WriteHeader. A
	// present-but-nil Content-Type deliberately suppresses that behavior.
	_, hasContentType := w.header["Content-Type"]
	if len(body) > 0 && len(w.c.Response().Body()) == 0 && !hasContentType {
		if !w.wroteHeader {
			w.header.Set("Content-Type", http.DetectContentType(body))
		} else if len(w.c.Response().Header.Peek("Content-Type")) == 0 {
			// Headers were copied to Fiber already; retain the committed status
			// and any content type supplied by a downstream Fiber handler.
			w.c.Response().Header.SetContentType(http.DetectContentType(body))
		}
	}
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	w.c.Response().AppendBody(body)
	return len(body), nil
}
