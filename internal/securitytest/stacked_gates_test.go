package securitytest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v3"
	authkitfiber "github.com/open-rails/authkit/adapters/fiber"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdpop"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// countingAuthority is a real authority that counts the requests it
// verifies.
type countingAuthority struct {
	verify.Authority
	verified atomic.Int32
}

func (c *countingAuthority) VerifyRequest(r *http.Request) (verify.Claims, error) {
	c.verified.Add(1)
	return c.Authority.VerifyRequest(r)
}

const resourceURL = "https://auth.security.test/resource"

// sendTo sends one POST to resourceURL with header through a net/http or Gin
// handler.
func sendTo(handler http.Handler) func(t *testing.T, header http.Header) response {
	return func(t *testing.T, header http.Header) response {
		r := httptest.NewRequest(http.MethodPost, resourceURL, nil)
		r.Header = header
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return response{status: w.Code, body: w.Body.Bytes()}
	}
}

func sendToFiber(app *fiber.App) func(t *testing.T, header http.Header) response {
	return func(t *testing.T, header http.Header) response {
		r := httptest.NewRequest(http.MethodPost, resourceURL, nil)
		r.Header = header
		resp, err := app.Test(r, fiber.TestConfig{Timeout: 30 * time.Second})
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return response{status: resp.StatusCode, body: body}
	}
}

// gate is one live gate in each framework's form.
type gate struct {
	http  func(http.Handler) http.Handler
	gin   gin.HandlerFunc
	fiber fiber.Handler
}

func requiredGate(a verify.Authority) gate {
	return gate{verify.Required(a), authkitgin.Required(a), authkitfiber.Required(a)}
}

func sensitiveGate(a verify.Authority) gate {
	return gate{verify.Sensitive(a), authkitgin.Sensitive(a), authkitfiber.Sensitive(a)}
}

func permissionGate(a verify.Authority, ref iam.GroupRef, perm iam.Perm) gate {
	return gate{verify.RequirePermissionOn(a, ref, perm), authkitgin.RequirePermissionOn(a, ref, perm), authkitfiber.RequirePermissionOn(a, ref, perm)}
}

// stacks mounts first then second on one route over net/http, Gin and
// Fiber.
func stacks(first, second gate) map[string]func(*testing.T, http.Header) response {
	noContent := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	g := gin.New()
	g.POST("/resource", first.gin, second.gin, func(c *gin.Context) { c.Status(http.StatusNoContent) })
	f := fiber.New()
	f.Post("/resource", first.fiber, second.fiber, func(c fiber.Ctx) error { return c.SendStatus(http.StatusNoContent) })
	return map[string]func(*testing.T, http.Header) response{
		"net/http": sendTo(first.http(second.http(noContent))),
		"gin":      sendTo(g),
		"fiber":    sendToFiber(f),
	}
}

// TestSecurityStackedGatesVerifyOnce (#418): live gates stacked on one route
// over one authority verify the request once and reuse its claims, so a
// DPoP proof is spent once (a second verification would be a replay the
// store refuses) and an API key is looked up once. Claims another
// authenticator verified, or a host stored with SetClaims, are verified
// again.
func TestSecurityStackedGatesVerifyOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const resource = "https://resource.security.test"
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC), authtest.WithConfig(withResourceClient(resource)))
	verifier, err := h.auth.NewVerifier([]string{resource})
	require.NoError(t, err)
	auth := &countingAuthority{Authority: verifier}

	// once asserts every stack answers want (and code, when set) with one
	// verification per request.
	once := func(t *testing.T, routes map[string]func(*testing.T, http.Header) response, header func() http.Header, want int, code string) {
		t.Helper()
		for name, send := range routes {
			auth.verified.Store(0)
			resp := send(t, header())
			require.Equal(t, want, resp.status, "%s: %s", name, resp)
			if code != "" {
				require.Equal(t, code, resp.errorCode(), name)
			}
			require.EqualValues(t, 1, auth.verified.Load(), "%s verified the request more than once", name)
		}
	}

	t.Run("DPoP-bound resource token", func(t *testing.T) {
		key := testdpop.Key(t)
		minted := h.resourceToken(h.login(h.newAccount("stackmod")).AccessToken, key)
		proven := func() http.Header {
			header := http.Header{}
			header.Set("Authorization", "DPoP "+minted)
			header.Set("DPoP", testdpop.Proof(t, key, http.MethodPost, resourceURL, minted, nil))
			return header
		}
		required := stacks(requiredGate(auth), requiredGate(auth))
		once(t, required, proven, http.StatusNoContent, "")
		// Sensitive reuses the claims too, then refuses: a resource token
		// carries no sign-in of this deployment to be recent.
		once(t, stacks(requiredGate(auth), sensitiveGate(auth)), proven, http.StatusForbidden, "forbidden")

		// The one verification spent the proof.
		header := proven()
		send := required["net/http"]
		require.Equal(t, http.StatusNoContent, send(t, header).status)
		require.Equal(t, http.StatusUnauthorized, send(t, header).status, "a replayed proof")
	})

	owner, manager := h.newAccount("stackowner"), h.newAccount("stackmanager")
	group, base := h.newOrg(owner)
	h.grant(group, manager, "manager")
	apiKey := h.issue(base+"/api-keys", h.login(manager).AccessToken, map[string]any{"name": "ci", "role": "org:member"})

	t.Run("API key", func(t *testing.T) {
		bearer := func() http.Header { return http.Header{"Authorization": {"Bearer " + apiKey.Secret}} }
		read := permissionGate(auth, group, newSecurityModel().catalogRead)

		once(t, stacks(requiredGate(auth), read), bearer, http.StatusNoContent, "")
		once(t, stacks(read, sensitiveGate(auth)), bearer, http.StatusForbidden, "forbidden")
	})

	t.Run("claims are reused only for the same authenticator and credential", func(t *testing.T) {
		token := h.login(h.newAccount("stackuser")).AccessToken
		noContent := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		// The Client admits its own audience; the resource verifier does not,
		// and verifies the request again rather than trusting the Client's
		// claims.
		resp := sendTo(verify.Required(h.auth)(verify.RequireSession(auth)(noContent)))(t, http.Header{"Authorization": {"Bearer " + token}})
		require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())

		// A request carrying another credential under verified claims (an
		// in-process sub-request) is verified for that credential.
		swap := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.Clone(r.Context())
				r.Header.Set("Authorization", "Bearer not-a-token")
				next.ServeHTTP(w, r)
			})
		}
		auth.verified.Store(0)
		resp = sendTo(verify.Required(auth)(swap(verify.Required(auth)(noContent))))(t, http.Header{"Authorization": {"Bearer " + apiKey.Secret}})
		require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
		require.EqualValues(t, 2, auth.verified.Load())

		// Claims a host stored never pass a gate.
		cl, err := h.auth.Verify(context.Background(), token)
		require.NoError(t, err)
		stored := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(verify.SetClaims(r.Context(), cl)))
			})
		}
		auth.verified.Store(0)
		resp = sendTo(stored(verify.RequireSession(auth)(noContent)))(t, http.Header{})
		require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
		require.EqualValues(t, 1, auth.verified.Load())
	})
}
