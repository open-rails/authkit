package authkitfiber_test

import (
	"context"
	"crypto"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	authkitfiber "github.com/open-rails/authkit/adapters/fiber"
	"github.com/open-rails/authkit/authhttp"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
)

func newMountService(t *testing.T) *authhttp.Service {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("AUTHKIT_TEST_REQUIRE_DB") == "1" {
			t.Fatal("AUTHKIT_TEST_DATABASE_URL not set but AUTHKIT_TEST_REQUIRE_DB=1")
		}
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	signer, err := jwtkit.NewRSASigner(2048, "native-mount-test")
	if err != nil {
		t.Fatal(err)
	}
	client, err := embedded.New(embedded.Config{
		Token: embedded.TokenConfig{
			Issuer: "https://example.com", IssuedAudiences: []string{"test-app"},
			ExpectedAudiences: []string{"test-app"}, AccessTokenDuration: time.Hour,
		},
		Keys: embedded.KeysConfig{Source: jwtkit.StaticKeySource{
			Active: signer, Pubs: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
		}},
		Ephemeral: embedded.EphemeralConfig{AllowMemory: true},
		Registration: embedded.RegistrationConfig{
			NativeUserMode: embedded.RegistrationModeOpen,
			Verification:   embedded.RegistrationVerificationNone,
		},
		Identity: embedded.IdentityConfig{Providers: []authprovider.Provider{
			authprovider.Google("google-client", "google-secret"),
		}},
	}, embedded.Deps{Postgres: pool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	svc, err := authhttp.New(client, authhttp.Config{DisableRateLimiting: true, DirectPeerIP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return svc
}

func TestMountRejectsInvalidConfiguration(t *testing.T) {
	if err := authkitfiber.Mount(nil, nil); err == nil {
		t.Fatal("nil app accepted")
	}
	app := fiber.New()
	if err := authkitfiber.Mount(app, nil); err == nil {
		t.Fatal("nil service accepted")
	}
	if err := authkitfiber.Mount(app, nil, authhttp.MountOptions{}, authhttp.MountOptions{}); err == nil {
		t.Fatal("multiple option values accepted")
	}
	if routes := app.GetRoutes(); len(routes) != 0 {
		t.Fatalf("invalid mounts registered routes: %+v", routes)
	}
}

func nativeTestPath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			parts[i] = ":" + part[1:len(part)-1]
		}
	}
	return strings.Join(parts, "/")
}

func concreteTestPath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") {
			parts[i] = "google"
		}
	}
	return strings.Join(parts, "/")
}

func TestMountRegistersNativeRoutesWithCanonicalGuards(t *testing.T) {
	svc := newMountService(t)
	for _, tc := range []struct {
		name string
		opts authhttp.MountOptions
	}{
		{name: "default"},
		{name: "selected groups and prefix", opts: authhttp.MountOptions{
			APIPrefix: "/identity", Groups: []authhttp.RouteGroup{authhttp.RouteAccount, authhttp.RouteAuth},
			ExcludeRoutes: []authhttp.RouteRef{{Method: http.MethodGet, Path: "/me"}},
		}},
		{name: "root prefix", opts: authhttp.MountOptions{APIPrefix: "/"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			canonical, err := authhttp.NewMount(svc, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			app := fiber.New()
			app.Get("/host-before", func(c fiber.Ctx) error { return c.SendString("before") })
			if err := authkitfiber.Mount(app, svc, tc.opts); err != nil {
				t.Fatal(err)
			}
			app.Get("/host-after", func(c fiber.Ctx) error { return c.SendString("after") })
			wantRoutes := make(map[string]string)
			for _, route := range canonical.Routes() {
				key := route.Method + " " + nativeTestPath(route.Path)
				wantRoutes[key] = authkitfiber.RouteNamePrefix + key
			}
			gotRoutes := make(map[string]string)
			for _, route := range app.GetRoutes() {
				if strings.HasPrefix(route.Name, authkitfiber.RouteNamePrefix) {
					key := route.Method + " " + route.Path
					if _, duplicate := gotRoutes[key]; duplicate {
						t.Errorf("duplicate native route %s", key)
					}
					gotRoutes[key] = route.Name
				}
			}
			if !reflect.DeepEqual(gotRoutes, wantRoutes) {
				t.Fatalf("native routes differ from canonical catalog\ngot: %v\nwant: %v", gotRoutes, wantRoutes)
			}
			for _, route := range canonical.Routes() {
				path := concreteTestPath(route.Path)
				r := httptest.NewRequest(route.Method, path, strings.NewReader("{}"))
				r.Header.Set("Content-Type", "application/json")
				want := httptest.NewRecorder()
				canonical.ServeHTTP(want, r)
				r = httptest.NewRequest(route.Method, path, strings.NewReader("{}"))
				r.Header.Set("Content-Type", "application/json")
				got, err := app.Test(r)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(got.Body)
				got.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if got.StatusCode != want.Code || got.Header.Get("Content-Type") != want.Header().Get("Content-Type") {
					t.Errorf("%s %s: native %d %q %q, canonical %d %q %q", route.Method, path,
						got.StatusCode, got.Header.Get("Content-Type"), body, want.Code, want.Header().Get("Content-Type"), want.Body.String())
				}
			}
			for _, path := range []string{"/host-before", "/host-after"} {
				if status, _, _ := request(t, app, http.MethodGet, path, ""); status != http.StatusOK {
					t.Errorf("host route %s: %d", path, status)
				}
			}
			if status, _, _ := request(t, app, http.MethodGet, "/not-an-authkit-route", ""); status != http.StatusNotFound {
				t.Errorf("unmatched route: %d", status)
			}
			if status, _, _ := request(t, app, http.MethodPost, authhttp.JWKSPath, ""); status != http.StatusMethodNotAllowed {
				t.Errorf("method mismatch: %d", status)
			}
		})
	}
}

func TestMountPreservesParametersContextAndJSONCookieGuards(t *testing.T) {
	svc := newMountService(t)
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.SetContext(context.WithValue(c.Context(), hostContextKey{}, "host"))
		return c.Next()
	})
	opts := authhttp.MountOptions{
		APIPrefix: "/identity", RefreshCookie: true,
		Wrap: func(spec authhttp.RouteSpec, handler http.Handler) http.Handler {
			if spec.Path != "/user/providers/{provider}" {
				return handler
			}
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Set-Cookie", "one=1")
				w.Header().Add("Set-Cookie", "two=2")
				io.WriteString(w, r.PathValue("provider")+":"+r.Context().Value(hostContextKey{}).(string))
			})
		},
	}
	if err := authkitfiber.Mount(app, svc, opts); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, contentType, origin, body string
		status                          int
	}{
		{"valid", "application/json", "https://example.com", "{}", http.StatusOK},
		{"non JSON", "text/plain", "https://example.com", "{}", http.StatusBadRequest},
		{"cross origin", "application/json", "http://attacker.example", "{}", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodDelete, "https://example.com/identity/user/providers/google", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.contentType)
			r.Header.Set("Origin", tc.origin)
			res, err := app.Test(r)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tc.status {
				t.Fatalf("status = %d %q, want %d", res.StatusCode, body, tc.status)
			}
			if tc.status == http.StatusOK {
				if string(body) != "google:host" {
					t.Errorf("lost route parameter or host context: %q", body)
				}
				if got := res.Header.Values("Set-Cookie"); !reflect.DeepEqual(got, []string{"one=1", "two=2"}) {
					t.Errorf("cookies = %v", got)
				}
			}
		})
	}
}

func TestMountRejectsUnsupportedPathsBeforeRegistration(t *testing.T) {
	svc := newMountService(t)
	for _, prefix := range []string{"/auth:prefix", "/auth+prefix", "/auth/{rest...}"} {
		app := fiber.New()
		if err := authkitfiber.Mount(app, svc, authhttp.MountOptions{APIPrefix: prefix}); err == nil {
			t.Fatalf("unsupported prefix %q accepted", prefix)
		}
		if routes := app.GetRoutes(); len(routes) != 0 {
			t.Fatalf("unsupported prefix %q left partial routes: %+v", prefix, routes)
		}
	}
}

func TestMountRejectsRouteCollisionsBeforeRegistration(t *testing.T) {
	svc := newMountService(t)
	app := fiber.New()
	app.Get("/api/v1/me", func(c fiber.Ctx) error { return c.SendString("host profile") }).Name("host.me")
	before := app.GetRoutes()
	if err := authkitfiber.Mount(app, svc); err == nil || !strings.Contains(err.Error(), "ExcludeRoutes") {
		t.Fatalf("collision error = %v", err)
	}
	after := app.GetRoutes()
	if len(after) != len(before) {
		t.Fatalf("collision registered partial AuthKit routes: got %d, started with %d", len(after), len(before))
	}
	for _, route := range after {
		if route.Name != "host.me" {
			t.Fatalf("collision renamed a host route: %+v", route)
		}
	}
	if err := authkitfiber.Mount(app, svc, authhttp.MountOptions{
		ExcludeRoutes: []authhttp.RouteRef{{Method: http.MethodGet, Path: "/me"}},
	}); err != nil {
		t.Fatal(err)
	}
	status, _, body := request(t, app, http.MethodGet, "/api/v1/me", "")
	if status != http.StatusOK || body != "host profile" {
		t.Fatalf("excluded replacement = %d %q", status, body)
	}
}

func TestMountCollisionChecksHonorFiberPathConfiguration(t *testing.T) {
	svc := newMountService(t)
	for _, tc := range []struct {
		name, path string
		config     fiber.Config
		collision  bool
	}{
		{name: "case insensitive", path: "/API/V1/ME", collision: true},
		{name: "trailing slash", path: "/api/v1/me/", collision: true},
		{name: "case and trailing slash", path: "/API/V1/ME/", collision: true},
		{name: "case sensitive", path: "/API/V1/ME", config: fiber.Config{CaseSensitive: true}},
		{name: "strict routing", path: "/api/v1/me/", config: fiber.Config{StrictRouting: true}},
		{name: "case sensitive still ignores slash", path: "/api/v1/me/", config: fiber.Config{CaseSensitive: true}, collision: true},
		{name: "strict still ignores case", path: "/API/V1/ME", config: fiber.Config{StrictRouting: true}, collision: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New(tc.config)
			app.Get(tc.path, func(c fiber.Ctx) error { return c.SendString("host profile") }).Name("host.me")
			before := app.GetRoutes()
			err := authkitfiber.Mount(app, svc)
			if tc.collision {
				if err == nil || !strings.Contains(err.Error(), "ExcludeRoutes") {
					t.Fatalf("collision error = %v", err)
				}
				if after := app.GetRoutes(); len(after) != len(before) {
					t.Fatalf("collision added routes: got %d, started with %d", len(after), len(before))
				}
			} else if err != nil {
				t.Fatal(err)
			}
			for _, route := range app.GetRoutes() {
				if route.Path == tc.path && route.Name != "host.me" {
					t.Errorf("host route renamed: %+v", route)
				}
			}
			status, _, body := request(t, app, http.MethodGet, tc.path, "")
			if status != http.StatusOK || body != "host profile" {
				t.Fatalf("host route = %d %q", status, body)
			}
		})
	}
}

func TestMountRejectsDisabledMethodsBeforeRegistration(t *testing.T) {
	svc := newMountService(t)
	for _, disabled := range []string{http.MethodHead, http.MethodPatch} {
		t.Run(disabled, func(t *testing.T) {
			var methods []string
			for _, method := range fiber.DefaultMethods {
				if method != disabled {
					methods = append(methods, method)
				}
			}
			app := fiber.New(fiber.Config{RequestMethods: methods})
			app.Add([]string{http.MethodGet}, "/host", func(c fiber.Ctx) error { return c.SendString("host") }).Name("host")
			before := app.GetRoutes()
			if err := authkitfiber.Mount(app, svc); err == nil || !strings.Contains(err.Error(), disabled) {
				t.Fatalf("disabled method error = %v", err)
			}
			after := app.GetRoutes()
			if len(after) != len(before) {
				t.Fatalf("disabled method added partial routes: got %d, started with %d", len(after), len(before))
			}
			for _, route := range after {
				if route.Name != "host" {
					t.Errorf("disabled method changed host route: %+v", route)
				}
			}
		})
	}
}
