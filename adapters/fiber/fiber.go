// Package authkitfiber bridges AuthKit's net/http middleware to Fiber v3.
// Mount registers AuthKit's routes directly on the application. Verification
// policy stays in verify. Handlers read the verified caller from c.Context()
// (verify.IdentityFromContext, verify.ClaimsFromContext) and write AuthKit errors
// with status, body := iam.ErrorResponse(err); c.Status(status).JSON(body).
package authkitfiber

import (
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
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

// Required is verify.Required in a Fiber chain: a is the *authkit.Client
// (or a *verify.Verifier).
func Required(a verify.Authenticator) fiber.Handler { return Use(verify.Required(a)) }

// Optional is verify.Optional in a Fiber chain.
func Optional(a verify.Authenticator) fiber.Handler { return Use(verify.Optional(a)) }

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

// SetGroup attaches the permission group the request acts in, for
// RequirePermission: call it from the handler that resolves the route's entity.
func SetGroup(c fiber.Ctx, ref iam.GroupRef) {
	c.SetContext(verify.WithGroup(c.Context(), ref))
}

// RequireSession is verify.RequireSession in a Fiber chain.
func RequireSession(a verify.Authority) fiber.Handler { return Use(verify.RequireSession(a)) }

// RequirePermission is verify.RequirePermission in a Fiber chain, in the
// group SetGroup attached.
func RequirePermission(a verify.Authority, perm iam.Perm) fiber.Handler {
	return Use(verify.RequirePermission(a, perm))
}

// RequirePermissionOn is verify.RequirePermissionOn in a Fiber chain.
func RequirePermissionOn(a verify.Authority, ref iam.GroupRef, perm iam.Perm) fiber.Handler {
	return Use(verify.RequirePermissionOn(a, ref, perm))
}

// Sensitive is verify.Sensitive in a Fiber chain.
func Sensitive(a verify.Authority) fiber.Handler { return Use(verify.Sensitive(a)) }

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
