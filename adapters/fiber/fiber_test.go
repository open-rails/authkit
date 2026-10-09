package authkitfiber_test

import (
	"bytes"
	"context"
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

	"github.com/open-rails/helpers/auth"

	"github.com/gofiber/fiber/v3"
	authkitfiber "github.com/open-rails/authkit/adapters/fiber"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testissuer"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/verify"
)

func newVerifier(t *testing.T, issuer *testissuer.Issuer, local bool, opts ...verify.VerifierOption) *verify.Verifier {
	t.Helper()
	v := verify.NewVerifier(opts...)
	if err := v.AddIssuer(issuer.URL(), []string{issuer.Audience()}, verify.IssuerOptions{
		IsLocal:   local,
		KeySource: testkeys.Source(issuer.Signer()),
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
	issuer := testissuer.New(t)
	v := newVerifier(t, issuer, true)
	cases := []struct {
		name                string
		v                   *verify.Verifier
		path, authorization string
	}{
		{"missing", v, "/posts", ""},
		{"valid", v, "/posts", "Bearer " + issuer.Token("user-1", "user@example.com", nil)},
		{"invalid", v, "/posts", "Bearer not-a-token"},
		{"wrong scheme", v, "/posts", "Basic abc"},
		{"expired", v, "/posts", "Bearer " + issuer.Token("user-1", "user@example.com", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})},
		{"wrong audience", v, "/posts", "Bearer " + issuer.Token("user-1", "user@example.com", map[string]any{"aud": "other-app"})},
		{"enrollment token blocked", v, "/posts", "Bearer " + issuer.Token("user-1", "user@example.com", map[string]any{"2fa_enrollment": true})},
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
						cl, _ := verify.ClaimsFromContext(c.Context())
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

func TestClaimsAndExternalPrincipal(t *testing.T) {
	issuer := testissuer.New(t)
	authTime := time.Now().Add(-time.Minute).Truncate(time.Second)
	token := issuer.Token("user-1", "user@example.com", map[string]any{
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
				cl, ok := verify.ClaimsFromContext(c.Context())
				if !ok {
					t.Error("verified claims missing")
				}
				p, ok := verify.IdentityFromContext(c.Context())
				if !ok || p.SubjectKind != auth.SubjectUser || p.Subject != "user-1" || p.Issuer != issuer.URL() || !p.SelfInvoked() {
					t.Errorf("identity = %+v, present = %v", p, ok)
				}
				if cl.IsUser() != local {
					t.Errorf("IsUser = %v, local = %v", cl.IsUser(), local)
				}
				if !local {
					if cl.UserID != "" || cl.Subject != "user-1" {
						t.Errorf("external claims = %+v", cl)
					}
					return c.SendStatus(http.StatusNoContent)
				}
				got := verify.Claims{UserID: cl.UserID, Email: cl.Email, EmailVerified: cl.EmailVerified, Username: cl.Username,
					SessionID: cl.SessionID, Entitlements: cl.Entitlements, AMR: cl.AMR, ACR: cl.ACR, AuthTime: cl.AuthTime, MFAEnrolled: cl.MFAEnrolled}
				want := verify.Claims{
					UserID: "user-1", Email: "user@example.com", EmailVerified: true,
					Username: "writer", SessionID: "session-1", Entitlements: []string{"blog"},
					AMR: []string{"pwd"}, ACR: "urn:example:loa:1", AuthTime: authTime, MFAEnrolled: true,
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("claims = %+v, want %+v", got, want)
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
		{Kind: iam.ActorAPIKey, APIKeyID: "machine-1", UserID: "must-not-be-used"},
		{Kind: iam.ActorRemoteApplication, RemoteApplicationID: "machine-2"},
		{Kind: iam.ActorDelegated, DelegatedSubject: "external-1", Issuer: "https://external.example"},
	} {
		app := fiber.New()
		app.Get("/", authkitfiber.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(verify.SetClaims(r.Context(), cl)))
			})
		}), func(c fiber.Ctx) error {
			if got, _ := verify.ClaimsFromContext(c.Context()); got.IsUser() {
				t.Error("an application or delegation exposed as a local user")
			}
			want, wantOK := cl.Identity()
			if p, ok := verify.IdentityFromContext(c.Context()); ok != wantOK || p != want {
				t.Errorf("identity = %+v, present = %v", p, ok)
			}
			if a, ok := verify.ActorFromContext(c.Context()); ok && a.Kind() == iam.ActorUser {
				t.Errorf("an application or delegation acts as user %v", a)
			}
			return c.SendStatus(http.StatusNoContent)
		})
		status, _, _ := request(t, app, http.MethodGet, "/", "")
		if status != http.StatusNoContent {
			t.Fatalf("status = %d", status)
		}
	}
}

func TestOptionalDoesNotLeakClaimsAcrossRequests(t *testing.T) {
	issuer := testissuer.New(t)
	app := fiber.New()
	app.Get("/", authkitfiber.Optional(newVerifier(t, issuer, true)), func(c fiber.Ctx) error {
		cl, _ := verify.ClaimsFromContext(c.Context())
		return c.SendString(cl.UserID)
	})
	for i := 0; i < 10; i++ {
		status, _, body := request(t, app, http.MethodGet, "/", "Bearer "+issuer.Token("user-1", "user@example.com", nil))
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
	issuer := testissuer.New(t)
	app := fiber.New()
	app.Get("/", authkitfiber.Optional(newVerifier(t, issuer, true)), func(c fiber.Ctx) error {
		cl, _ := verify.ClaimsFromContext(c.Context())
		return c.SendString(cl.UserID)
	})
	// Complete Fiber's lazy startup before driving concurrent requests.
	request(t, app, http.MethodGet, "/", "")
	for i := 0; i < 24; i++ {
		userID := fmt.Sprintf("user-%d", i)
		token := issuer.Token(userID, userID+"@example.com", nil)
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

// authority is a verify.Authority whose Can is f.
type authority struct {
	v *verify.Verifier
	f func(context.Context, iam.Actor, iam.GroupRef, iam.Perm) (bool, error)
}

func (a authority) VerifyRequest(r *http.Request) (verify.Claims, error) { return a.v.VerifyRequest(r) }
func (authority) CheckSession(context.Context, verify.Claims) error      { return nil }
func (a authority) Can(ctx context.Context, actor iam.Actor, ref iam.GroupRef, perm iam.Perm) (bool, error) {
	return a.f(ctx, actor, ref, perm)
}
func (authority) KnownPermission(perm iam.Perm) bool { return perm.String() == "blog:posts:write" }
func (authority) CheckRecentSignIn(context.Context, verify.Claims) error {
	return iam.ErrSessionRevoked
}

func TestRequirePermissionAuthenticatesAndChecksTheResolvedGroup(t *testing.T) {
	issuer := testissuer.New(t)
	group := iam.GroupByID("0190e2b6-0000-7000-8000-000000000001")
	for _, allow := range []bool{true, false} {
		calls := 0
		auth := authority{v: newVerifier(t, issuer, true), f: func(ctx context.Context, actor iam.Actor, ref iam.GroupRef, perm iam.Perm) (bool, error) {
			calls++
			if actor.Kind() != iam.ActorUser || actor.ID() != "user-1" || ref != group || perm.String() != "blog:posts:write" {
				t.Errorf("permission input = %v %v %q", actor, ref, perm)
			}
			return allow, nil
		}}
		app := fiber.New()
		load := func(c fiber.Ctx) error {
			authkitfiber.SetGroup(c, iam.GroupByID(c.Params("blog")))
			return c.Next()
		}
		app.Get("/unloaded/:blog", authkitfiber.RequirePermission(auth, ident.Perm("blog:posts:write")), func(c fiber.Ctx) error {
			t.Error("a route with no group reached its handler")
			return nil
		})
		app.Get("/blogs/:blog", load, authkitfiber.RequirePermission(auth, ident.Perm("blog:posts:write")), func(c fiber.Ctx) error {
			if !allow {
				t.Error("denied permission reached handler")
			}
			return c.SendStatus(http.StatusNoContent)
		})
		status, _, body := request(t, app, http.MethodGet, "/blogs/"+group.ID(), "")
		if status != http.StatusUnauthorized || calls != 0 {
			t.Fatalf("anonymous response = %d %q, calls = %d", status, body, calls)
		}
		status, _, body = request(t, app, http.MethodGet, "/blogs/"+group.ID(), "Bearer "+issuer.Token("user-1", "user@example.com", nil))
		want := http.StatusForbidden
		if allow {
			want = http.StatusNoContent
		}
		if status != want || calls != 1 {
			t.Fatalf("response = %d %q, calls = %d; want %d and one lookup", status, body, calls, want)
		}
		status, _, body = request(t, app, http.MethodGet, "/unloaded/"+group.ID(), "Bearer "+issuer.Token("user-1", "user@example.com", nil))
		if status != http.StatusInternalServerError || calls != 1 {
			t.Fatalf("no group: %d %q, calls = %d; want a closed 500 with no lookup", status, body, calls)
		}
	}
}

func TestRequirePermissionPanicsOnUnregisteredPermission(t *testing.T) {
	auth := authority{f: func(context.Context, iam.Actor, iam.GroupRef, iam.Perm) (bool, error) { return true, nil }}
	defer func() {
		if recover() == nil {
			t.Fatal("an unregistered permission must panic when the route is built")
		}
	}()
	authkitfiber.RequirePermission(auth, ident.Perm("blog:posts:delete"))
}

func TestMountPreservesHTTPResponses(t *testing.T) {
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
	if err := authkitfiber.Mount(app, surface{mux, []string{"POST /api/items/{id}"}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{http.MethodGet, "/health", http.StatusOK, "healthy"},
		{http.MethodPost, "/api/items/123?q=value", http.StatusCreated, "123:value"},
		{http.MethodGet, "/api/items/123", http.StatusMethodNotAllowed, "Method Not Allowed"},
		{http.MethodGet, "/missing", http.StatusNotFound, "Not Found"},
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

func TestMountDoesNotInventContentTypeForHTTPHandler(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		app := fiber.New()
		app.Use(func(c fiber.Ctx) error {
			if explicit {
				c.Set("Content-Type", "application/custom")
			}
			return c.Next()
		})
		if err := authkitfiber.Mount(app, surface{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/destination", http.StatusFound)
		}), []string{"GET /x"}}); err != nil {
			t.Fatal(err)
		}
		status, headers, body := request(t, app, http.MethodGet, "/x", "")
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

func TestMountContentTypeAfterExplicitStatus(t *testing.T) {
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
			if err := authkitfiber.Mount(app, surface{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.setHeader != nil {
					tc.setHeader(w.Header())
				}
				w.WriteHeader(http.StatusCreated)
				w.Write(nil)
				io.WriteString(w, "<html>first body</html>")
				io.WriteString(w, "plain suffix")
			}), []string{"GET /x"}}); err != nil {
				t.Fatal(err)
			}
			status, headers, body := request(t, app, http.MethodGet, "/x", "")
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

// surface mounts a plain handler under fixed patterns.
type surface struct {
	handler  http.Handler
	patterns []string
}

func (s surface) Handler() http.Handler { return s.handler }
func (s surface) Routes() []iam.Route {
	out := make([]iam.Route, 0, len(s.patterns))
	for _, p := range s.patterns {
		method, path, _ := strings.Cut(p, " ")
		out = append(out, iam.Route{Method: method, Path: path})
	}
	return out
}

// A Fiber handler behind Required reads the verified caller from c.Context(),
// the same call net/http and Gin handlers make.
func TestActorFromContextBehindRequired(t *testing.T) {
	issuer := testissuer.New(t)
	app := fiber.New()
	app.Get("/", authkitfiber.Required(newVerifier(t, issuer, true)), func(c fiber.Ctx) error {
		actor, ok := verify.ActorFromContext(c.Context())
		if !ok || actor.Kind() != iam.ActorUser {
			t.Errorf("actor = %v, %v", actor, ok)
		}
		return c.SendString(actor.ID())
	})
	status, _, body := request(t, app, http.MethodGet, "/", "Bearer "+issuer.Token("user-1", "user@example.com", nil))
	if status != http.StatusOK || body != "user-1" {
		t.Fatalf("got %d %q", status, body)
	}
	if status, _, _ := request(t, app, http.MethodGet, "/", ""); status != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d; Required must stop before the handler", status)
	}
}
