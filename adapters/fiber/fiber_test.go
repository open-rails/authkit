package authkitfiber_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	authkit "github.com/open-rails/authkit"
	authkitfiber "github.com/open-rails/authkit/adapters/fiber"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
)

func newIssuer(t *testing.T) *authtest.TestIssuer {
	t.Helper()
	issuer := authtest.NewTestIssuer()
	t.Cleanup(issuer.Close)
	return issuer
}

func newVerifier(t *testing.T, issuer *authtest.TestIssuer, local bool, opts ...verify.VerifierOption) *verify.Verifier {
	t.Helper()
	v := verify.NewVerifier(opts...)
	pub := issuer.Signer().(jwtkit.PublicKeySigner).PublicKey()
	if err := v.AddIssuer(issuer.URL(), []string{issuer.Audience()}, verify.IssuerOptions{
		IsLocal: local,
		RawKeys: map[string]crypto.PublicKey{issuer.Signer().KID(): pub},
	}); err != nil {
		t.Fatal(err)
	}
	return v
}

func request(t *testing.T, app *fiber.App, method, path, authorization string) (int, http.Header, string) {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	res, err := app.Test(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, res.Header, string(body)
}

// Compare the actual status and error body to the canonical net/http pipeline,
// including Optional's rejection of present-but-invalid credentials.
func TestRequiredOptionalParity(t *testing.T) {
	issuer := newIssuer(t)
	v := newVerifier(t, issuer, true)
	mfa := newVerifier(t, issuer, true, verify.WithRequireMFAEnrollment(true))
	mfa.AddMFAEnrollmentExemptRoutes([]string{"/api/v1/user/2fa"})
	cases := []struct {
		name                string
		v                   *verify.Verifier
		path, authorization string
	}{
		{"missing", v, "/posts", ""},
		{"valid", v, "/posts", "Bearer " + issuer.CreateToken("user-1", "user@example.com")},
		{"invalid", v, "/posts", "Bearer not-a-token"},
		{"wrong scheme", v, "/posts", "Basic abc"},
		{"expired", v, "/posts", "Bearer " + issuer.CreateExpiredToken("user-1", "user@example.com")},
		{"wrong audience", v, "/posts", "Bearer " + issuer.CreateTokenWithClaims("user-1", "user@example.com", map[string]any{"aud": "other-app"})},
		{"enrollment token blocked", v, "/posts", "Bearer " + issuer.CreateTokenWithClaims("user-1", "user@example.com", map[string]any{"2fa_enrollment": true})},
		{"mfa required", mfa, "/posts", "Bearer " + issuer.CreateToken("user-1", "user@example.com")},
		{"mfa enrolled", mfa, "/posts", "Bearer " + issuer.CreateTokenWithClaims("user-1", "user@example.com", map[string]any{"mfa_enrolled": true})},
		{"mfa exempt", mfa, "/api/v1/user/2fa", "Bearer " + issuer.CreateToken("user-1", "user@example.com")},
		{"mfa suffix is not exempt", mfa, "/other/api/v1/user/2fa", "Bearer " + issuer.CreateToken("user-1", "user@example.com")},
	}
	for _, optional := range []bool{false, true} {
		name := "required"
		if optional {
			name = "optional"
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					canonical, adapter := verify.Required(tc.v), authkitfiber.Required(tc.v)
					if optional {
						canonical, adapter = verify.Optional(tc.v), authkitfiber.Optional(tc.v)
					}
					want := httptest.NewRecorder()
					r := httptest.NewRequest(http.MethodGet, tc.path, nil)
					r.Header.Set("Authorization", tc.authorization)
					canonical(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						cl, _ := verify.ClaimsFromContext(r.Context())
						io.WriteString(w, "user:"+cl.UserID)
					})).ServeHTTP(want, r)
					app := fiber.New()
					app.Get(tc.path, adapter, func(c fiber.Ctx) error {
						cl, _ := authkitfiber.Claims(c)
						return c.SendString("user:" + cl.UserID)
					})
					status, headers, body := request(t, app, http.MethodGet, tc.path, tc.authorization)
					if status != want.Code || body != want.Body.String() {
						t.Fatalf("got %d %q; canonical %d %q", status, body, want.Code, want.Body.String())
					}
					if status >= 400 && headers.Get("Content-Type") != want.Header().Get("Content-Type") {
						t.Fatalf("error content type = %q, want %q", headers.Get("Content-Type"), want.Header().Get("Content-Type"))
					}
				})
			}
		})
	}
}

func TestUserClaimsAndExternalPrincipal(t *testing.T) {
	issuer := newIssuer(t)
	authTime := time.Now().Add(-time.Minute).Truncate(time.Second)
	token := issuer.CreateTokenWithClaims("user-1", "user@example.com", map[string]any{
		"email_verified": true, "username": "writer", "sid": "session-1",
		"entitlements": []string{"blog"}, "amr": []string{"pwd"},
		"acr": "urn:example:loa:1", "auth_time": authTime.Unix(), "mfa_enrolled": true,
	})
	for _, local := range []bool{true, false} {
		name := "external"
		if local {
			name = "local"
		}
		t.Run(name, func(t *testing.T) {
			app := fiber.New()
			app.Get("/", authkitfiber.Required(newVerifier(t, issuer, local)), func(c fiber.Ctx) error {
				cl, ok := authkitfiber.Claims(c)
				if !ok {
					t.Error("verified claims missing")
				}
				p, ok := authkitfiber.Principal(c)
				if !ok || p.Kind != authkit.PrincipalKindUser || p.Subject != "user-1" || p.Issuer != issuer.URL() {
					t.Errorf("principal = %+v, present = %v", p, ok)
				}
				user, ok := authkitfiber.UserClaims(c)
				if ok != local {
					t.Errorf("UserClaims present = %v, local = %v", ok, local)
				}
				if !local {
					if cl.UserID != "" || cl.Subject != "user-1" {
						t.Errorf("external claims = %+v", cl)
					}
					return c.SendStatus(http.StatusNoContent)
				}
				want := authkitfiber.UserClaimsData{
					UserID: "user-1", Email: "user@example.com", EmailVerified: true,
					Username: "writer", SessionID: "session-1", Entitlements: []string{"blog"},
					AMR: []string{"pwd"}, ACR: "urn:example:loa:1", AuthTime: authTime, MFAEnrolled: true,
				}
				if !reflect.DeepEqual(user, want) {
					t.Errorf("user = %+v, want %+v", user, want)
				}
				user.Entitlements[0], user.AMR[0] = "mutated", "mutated"
				again, _ := authkitfiber.UserClaims(c)
				if again.Entitlements[0] != "blog" || again.AMR[0] != "pwd" {
					t.Error("UserClaims exposes mutable claim slices")
				}
				return c.SendStatus(http.StatusNoContent)
			})
			status, _, body := request(t, app, http.MethodGet, "/", "Bearer "+token)
			if status != http.StatusNoContent {
				t.Fatalf("status %d: %s", status, body)
			}
		})
	}
}

func TestAccessorsRejectMachineClaimsAsUsers(t *testing.T) {
	for _, cl := range []verify.Claims{
		{TokenType: verify.APIKeyPrincipalType, RemoteApplicationID: "machine-1", UserID: "must-not-be-used"},
		{TokenType: verify.RemoteApplicationTokenType, RemoteApplicationID: "machine-2"},
		{DelegatedSubject: "external-1", Issuer: "https://external.example"},
	} {
		app := fiber.New()
		app.Get("/", authkitfiber.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(verify.SetClaims(r.Context(), cl)))
			})
		}), func(c fiber.Ctx) error {
			if _, ok := authkitfiber.UserClaims(c); ok {
				t.Error("machine/delegated principal exposed as a local user")
			}
			if p, ok := authkitfiber.Principal(c); !ok || p != cl.Principal() {
				t.Errorf("principal = %+v, present = %v", p, ok)
			}
			return c.SendStatus(http.StatusNoContent)
		})
		status, _, _ := request(t, app, http.MethodGet, "/", "")
		if status != http.StatusNoContent {
			t.Fatalf("status = %d", status)
		}
	}
	if _, ok := authkitfiber.Claims(nil); ok {
		t.Error("nil context has claims")
	}
	if _, ok := authkitfiber.UserClaims(nil); ok {
		t.Error("nil context has user")
	}
	if _, ok := authkitfiber.Principal(nil); ok {
		t.Error("nil context has principal")
	}
}

func TestOptionalDoesNotLeakClaimsAcrossRequests(t *testing.T) {
	issuer := newIssuer(t)
	app := fiber.New()
	app.Get("/", authkitfiber.Optional(newVerifier(t, issuer, true)), func(c fiber.Ctx) error {
		user, _ := authkitfiber.UserClaims(c)
		return c.SendString(user.UserID)
	})
	for i := 0; i < 10; i++ {
		status, _, body := request(t, app, http.MethodGet, "/", "Bearer "+issuer.CreateToken("user-1", "user@example.com"))
		if status != http.StatusOK || body != "user-1" {
			t.Fatalf("authenticated = %d %q", status, body)
		}
		status, _, body = request(t, app, http.MethodGet, "/", "")
		if status != http.StatusOK || body != "" {
			t.Fatalf("anonymous inherited claims: %d %q", status, body)
		}
	}
}

func TestConcurrentRequestsKeepClaimsIsolated(t *testing.T) {
	issuer := newIssuer(t)
	app := fiber.New()
	app.Get("/", authkitfiber.Optional(newVerifier(t, issuer, true)), func(c fiber.Ctx) error {
		user, _ := authkitfiber.UserClaims(c)
		return c.SendString(user.UserID)
	})
	// Complete Fiber's lazy startup before driving concurrent requests.
	request(t, app, http.MethodGet, "/", "")
	for i := 0; i < 24; i++ {
		userID := fmt.Sprintf("user-%d", i)
		token := issuer.CreateToken(userID, userID+"@example.com")
		t.Run(userID, func(t *testing.T) {
			t.Parallel()
			for j := 0; j < 3; j++ {
				status, _, body := request(t, app, http.MethodGet, "/", "Bearer "+token)
				if status != http.StatusOK || body != userID {
					t.Fatalf("got %d %q for %s", status, body, userID)
				}
				status, _, body = request(t, app, http.MethodGet, "/", "")
				if status != http.StatusOK || body != "" {
					t.Fatalf("anonymous request inherited claims: %d %q", status, body)
				}
			}
		})
	}
}

// Use must carry the TLS state from the real connection into net/http
// middleware: receiver-bound credentials compare against its peer certificate.
func TestUsePreservesActualTLSPeerCertificate(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(serial int64, name string, usage x509.ExtKeyUsage) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	serverCert := issue(2, "test-server", x509.ExtKeyUsageServerAuth)
	clientCert := issue(3, "test-client", x509.ExtKeyUsageClientAuth)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	app.Get("/", authkitfiber.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
				t.Error("converted request lost verified TLS peer state")
				http.Error(w, "missing TLS peer", http.StatusUnauthorized)
				return
			}
			peer := r.TLS.PeerCertificates[0]
			if !bytes.Equal(peer.Raw, clientCert.Certificate[0]) {
				t.Error("converted request carries the wrong peer certificate")
			}
			ctx := context.WithValue(r.Context(), middlewareContextKey{}, peer.Subject.CommonName)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}), func(c fiber.Ctx) error {
		peer, _ := c.Context().Value(middlewareContextKey{}).(string)
		return c.SendString(peer)
	})
	served := make(chan error, 1)
	go func() { served <- app.Listener(listener, fiber.ListenConfig{DisableStartupMessage: true}) }()
	t.Cleanup(func() {
		if err := app.ShutdownWithTimeout(5 * time.Second); err != nil {
			t.Error(err)
		}
		listener.Close()
		if err := <-served; err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{clientCert},
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	res, err := client.Get("https://" + listener.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || string(body) != "test-client" {
		t.Fatalf("TLS response = %d %q", res.StatusCode, body)
	}
}

type hostContextKey struct{}
type middlewareContextKey struct{}

func TestUsePreservesHostContextAndMiddlewareOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), hostContextKey{}, "host-value"))
	cancel()
	var sequence []string
	wrap := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sequence = append(sequence, name+":before")
				if r.Context().Value(hostContextKey{}) != "host-value" || !errors.Is(r.Context().Err(), context.Canceled) {
					t.Error("net/http middleware lost host context or cancellation")
				}
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middlewareContextKey{}, name)))
				sequence = append(sequence, name+":after")
			})
		}
	}
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error { c.SetContext(ctx); return c.Next() })
	app.Get("/", authkitfiber.Use(wrap("first"), nil, wrap("second")), func(c fiber.Ctx) error {
		sequence = append(sequence, "handler")
		if c.Context().Value(hostContextKey{}) != "host-value" || c.Context().Value(middlewareContextKey{}) != "second" || !errors.Is(c.Context().Err(), context.Canceled) {
			t.Error("Fiber handler lost host or middleware context")
		}
		return c.Status(http.StatusAccepted).SendString("accepted")
	})
	status, _, body := request(t, app, http.MethodGet, "/", "")
	if status != http.StatusAccepted || body != "accepted" {
		t.Fatalf("response = %d %q", status, body)
	}
	if want := []string{"first:before", "second:before", "handler", "second:after", "first:after"}; !reflect.DeepEqual(sequence, want) {
		t.Fatalf("sequence = %v, want %v", sequence, want)
	}
}

func TestUseAbortAndFiberErrors(t *testing.T) {
	t.Run("abort", func(t *testing.T) {
		app := fiber.New()
		app.Get("/", authkitfiber.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "denied", http.StatusForbidden)
			})
		}), func(c fiber.Ctx) error {
			t.Error("aborted middleware ran next handler")
			return c.SendString("should not run")
		})
		status, headers, body := request(t, app, http.MethodGet, "/", "")
		if status != http.StatusForbidden || body != "denied\n" || headers.Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("response = %d %q %v", status, body, headers)
		}
	})
	t.Run("fiber error handler", func(t *testing.T) {
		errBoom := errors.New("handler failed")
		app := fiber.New(fiber.Config{ErrorHandler: func(c fiber.Ctx, err error) error {
			if !errors.Is(err, errBoom) {
				t.Errorf("error = %v", err)
			}
			c.Set("X-Error", "handled")
			return c.Status(http.StatusConflict).SendString("handled failure")
		}})
		app.Get("/", authkitfiber.Use(), func(c fiber.Ctx) error { return errBoom })
		status, headers, body := request(t, app, http.MethodGet, "/", "")
		if status != http.StatusConflict || body != "handled failure" || headers.Get("X-Error") != "handled" {
			t.Fatalf("response = %d %q %v", status, body, headers)
		}
	})
}

type permissionChecker func(context.Context, authkit.Subject, string, authkit.Perm) (bool, error)

func (f permissionChecker) CanOnGroup(ctx context.Context, subject authkit.Subject, group string, perm authkit.Perm) (bool, error) {
	return f(ctx, subject, group, perm)
}

func TestRequirePermissionPropagatesResolvedScope(t *testing.T) {
	issuer := newIssuer(t)
	scope := verify.PermissionScope{GroupID: "group-uuid", AuthorityIssuer: issuer.URL(), Persona: "blog", Instance: "writers"}
	for _, allow := range []bool{true, false} {
		calls := 0
		checker := permissionChecker(func(ctx context.Context, subject authkit.Subject, group string, perm authkit.Perm) (bool, error) {
			calls++
			if subject != authkit.UserSubject("user-1") || group != scope.GroupID || perm != "blog:posts:write" {
				t.Errorf("permission input = %v %q %q", subject, group, perm)
			}
			return allow, nil
		})
		app := fiber.New()
		app.Get("/blogs/:blog", authkitfiber.Required(newVerifier(t, issuer, true)), authkitfiber.RequirePermission(checker, "blog:posts:write", func(c fiber.Ctx) verify.PermissionScope {
			if c.Params("blog") != "writers" {
				t.Errorf("route param = %q", c.Params("blog"))
			}
			return scope
		}), func(c fiber.Ctx) error {
			if !allow {
				t.Error("denied permission reached handler")
			}
			got, ok := verify.PermissionScopeFromContext(c.Context())
			if !ok || got != scope {
				t.Errorf("scope = %+v, present = %v", got, ok)
			}
			return c.SendStatus(http.StatusNoContent)
		})
		status, _, body := request(t, app, http.MethodGet, "/blogs/writers", "Bearer "+issuer.CreateToken("user-1", "user@example.com"))
		want := http.StatusForbidden
		if allow {
			want = http.StatusNoContent
		}
		if status != want || calls != 1 {
			t.Fatalf("response = %d %q, calls = %d; want %d and one lookup", status, body, calls, want)
		}
	}
}

type livenessSource func(context.Context, []string) (map[string]authkit.UserLiveness, error)

func (f livenessSource) UserLivenessByIDs(ctx context.Context, ids []string) (map[string]authkit.UserLiveness, error) {
	return f(ctx, ids)
}

func TestRequiredLive(t *testing.T) {
	issuer := newIssuer(t)
	for _, v := range []*verify.Verifier{nil, newVerifier(t, issuer, true)} {
		if middleware, err := authkitfiber.RequiredLive(v); middleware != nil || !errors.Is(err, verify.ErrLivenessUnconfigured) {
			t.Fatalf("unconfigured RequiredLive = %v, middleware nil = %v", err, middleware == nil)
		}
	}
	cases := []struct {
		name   string
		live   map[string]authkit.UserLiveness
		err    error
		status int
	}{
		{"allowed", map[string]authkit.UserLiveness{"user-1": {Allowed: true, Username: "fresh", Email: "fresh@example.com", EmailVerified: true}}, nil, http.StatusOK},
		{"disabled", map[string]authkit.UserLiveness{"user-1": {Allowed: false}}, nil, http.StatusUnauthorized},
		{"missing", nil, nil, http.StatusUnauthorized},
		{"unavailable", nil, errors.New("directory unavailable"), http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			v := newVerifier(t, issuer, true).WithLiveness(livenessSource(func(ctx context.Context, ids []string) (map[string]authkit.UserLiveness, error) {
				calls++
				if !reflect.DeepEqual(ids, []string{"user-1"}) {
					t.Errorf("liveness IDs = %v", ids)
				}
				return tc.live, tc.err
			}))
			middleware, err := authkitfiber.RequiredLive(v)
			if err != nil {
				t.Fatal(err)
			}
			app := fiber.New()
			app.Get("/", middleware, func(c fiber.Ctx) error {
				user, ok := authkitfiber.UserClaims(c)
				if !ok || user.Username != "fresh" || user.Email != "fresh@example.com" || !user.EmailVerified {
					t.Errorf("fresh user = %+v, present = %v", user, ok)
				}
				return c.SendString(user.Username)
			})
			for i := 0; i < 2; i++ {
				status, _, body := request(t, app, http.MethodGet, "/", "Bearer "+issuer.CreateToken("user-1", "stale@example.com"))
				if status != tc.status {
					t.Fatalf("status = %d %q, want %d", status, body, tc.status)
				}
			}
			if calls != 2 {
				t.Errorf("liveness calls = %d, want one per request", calls)
			}
		})
	}
}

func TestFallbackPreservesHTTPRouting(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Del("X-Remove")
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, r.PathValue("id")+":"+r.URL.Query().Get("q"))
	})
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.Response().Header.Add("Set-Cookie", "host=1")
		c.Set("X-Remove", "upstream")
		return c.Next()
	})
	app.Get("/health", func(c fiber.Ctx) error { return c.SendString("healthy") })
	app.Use(authkitfiber.Fallback(mux))
	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{http.MethodGet, "/health", http.StatusOK, "healthy"},
		{http.MethodPost, "/api/items/123?q=value", http.StatusCreated, "123:value"},
		{http.MethodGet, "/api/items/123", http.StatusMethodNotAllowed, "Method Not Allowed"},
		{http.MethodGet, "/missing", http.StatusNotFound, "404 page not found"},
	} {
		status, headers, body := request(t, app, tc.method, tc.path, "")
		if status != tc.status || !strings.Contains(body, tc.body) {
			t.Fatalf("%s %s = %d %q, want %d %q", tc.method, tc.path, status, body, tc.status, tc.body)
		}
		if tc.status == http.StatusCreated {
			if got := headers.Get("Content-Type"); got != "text/plain; charset=utf-8" {
				t.Errorf("content type after explicit status = %q", got)
			}
			if !reflect.DeepEqual(headers.Values("Set-Cookie"), []string{"host=1", "a=1", "b=2"}) {
				t.Errorf("cookies = %v", headers.Values("Set-Cookie"))
			}
			if headers.Get("X-Remove") != "" {
				t.Errorf("HTTP Header.Del did not remove host response header: %v", headers)
			}
		}
	}
}

func TestFallbackDoesNotInventContentTypeForHTTPHandler(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		app := fiber.New()
		app.Use(func(c fiber.Ctx) error {
			if explicit {
				c.Set("Content-Type", "application/custom")
			}
			return c.Next()
		})
		app.Use(authkitfiber.Fallback(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/destination", http.StatusFound)
		})))
		status, headers, body := request(t, app, http.MethodGet, "/", "")
		if status != http.StatusFound || headers.Get("Location") != "/destination" {
			t.Fatalf("redirect = %d %v %q", status, headers, body)
		}
		if explicit {
			if headers.Get("Content-Type") != "application/custom" || body != "" {
				t.Errorf("explicit host content type not preserved: %v %q", headers, body)
			}
		} else if headers.Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(body, "/destination") {
			t.Errorf("Fiber default content type changed net/http.Redirect: %v %q", headers, body)
		}
	}
}

func TestFallbackContentTypeAfterExplicitStatus(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		setHeader  func(http.Header)
	}{
		{name: "sniff", want: "text/html; charset=utf-8"},
		{name: "explicit", want: "application/custom", setHeader: func(h http.Header) { h.Set("Content-Type", "application/custom") }},
		{name: "suppressed", setHeader: func(h http.Header) { h["Content-Type"] = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			app.Use(authkitfiber.Fallback(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.setHeader != nil {
					tc.setHeader(w.Header())
				}
				w.WriteHeader(http.StatusCreated)
				w.Write(nil)
				io.WriteString(w, "<html>first body</html>")
				io.WriteString(w, "plain suffix")
			})))
			status, headers, body := request(t, app, http.MethodGet, "/", "")
			if status != http.StatusCreated || headers.Get("Content-Type") != tc.want || body != "<html>first body</html>plain suffix" {
				t.Fatalf("response = %d %v %q; want content type %q", status, headers, body, tc.want)
			}
		})
	}
}

func TestUseWriteAfterNextPreservesFiberContentType(t *testing.T) {
	app := fiber.New()
	app.Get("/", authkitfiber.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Let the downstream handler choose its own content type.
			w.Header().Del("Content-Type")
			next.ServeHTTP(w, r)
			io.WriteString(w, "<html>suffix</html>")
		})
	}), func(c fiber.Ctx) error {
		c.Set("Content-Type", "application/custom")
		return c.Status(http.StatusAccepted).Send(nil)
	})
	status, headers, body := request(t, app, http.MethodGet, "/", "")
	if status != http.StatusAccepted || headers.Get("Content-Type") != "application/custom" || body != "<html>suffix</html>" {
		t.Fatalf("response = %d %v %q", status, headers, body)
	}
}

func TestOptionalLive(t *testing.T) {
	if middleware, err := authkitfiber.OptionalLive(nil); middleware != nil || !errors.Is(err, verify.ErrLivenessUnconfigured) {
		t.Fatalf("missing source: middleware=%v error=%v", middleware, err)
	}
	issuer := newIssuer(t)
	calls := 0
	allowed := true
	verifier := newVerifier(t, issuer, true).WithLiveness(livenessSource(func(_ context.Context, ids []string) (map[string]authkit.UserLiveness, error) {
		calls++
		return map[string]authkit.UserLiveness{ids[0]: {ID: ids[0], Allowed: allowed, Username: "fresh"}}, nil
	}))
	middleware, err := authkitfiber.OptionalLive(verifier)
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	app.Use(middleware)
	app.Get("/", func(c fiber.Ctx) error {
		user, ok := authkitfiber.UserClaims(c)
		if !ok {
			return c.SendString("anonymous")
		}
		return c.SendString(user.Username)
	})
	for _, tc := range []struct {
		header, body  string
		status, calls int
	}{
		{body: "anonymous", status: 200},
		{header: "Bearer invalid", status: 401},
		{header: "Bearer " + issuer.CreateToken("user-1", "old@test"), body: "fresh", status: 200, calls: 1},
	} {
		status, _, body := request(t, app, http.MethodGet, "/", tc.header)
		if status != tc.status || calls != tc.calls || (tc.body != "" && body != tc.body) {
			t.Fatalf("optional live: status=%d body=%q calls=%d; want %+v", status, body, calls, tc)
		}
	}
	allowed = false
	status, _, _ := request(t, app, http.MethodGet, "/", "Bearer "+issuer.CreateToken("user-1", "old@test"))
	if status != http.StatusUnauthorized || calls != 2 {
		t.Fatalf("banned: status=%d calls=%d", status, calls)
	}
}
