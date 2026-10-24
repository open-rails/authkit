package critical_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v3"
	"github.com/open-rails/authkit"
	authkitfiber "github.com/open-rails/authkit/adapters/fiber"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testclock"
)

func wire(t *testing.T, client *http.Client, method, address, credential, mediaType, body string, headers http.Header) response {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), method, address, strings.NewReader(body))
	noError(t, err)
	if credential != "" {
		r.Header.Set("Authorization", "Bearer "+credential)
	}
	if mediaType != "" {
		r.Header.Set("Content-Type", mediaType)
	}
	for k, v := range headers {
		r.Header[k] = append([]string(nil), v...)
	}
	got, err := client.Do(r)
	noError(t, err)
	defer got.Body.Close()
	data, err := io.ReadAll(got.Body)
	noError(t, err)
	return response{status: got.StatusCode, header: got.Header, body: data}
}

func TestCriticalTransport(t *testing.T) {
	t.Run("AK-J31-C02_real_Gin_and_Fiber_keep_each_authority_gate", func(t *testing.T) {
		for _, adapter := range []string{"gin", "fiber"} {
			t.Run(adapter, func(t *testing.T) {
				f := newFixture(t)
				var address string
				if adapter == "gin" {
					router := gin.New()
					noError(t, authkitgin.Mount(router, f.auth))
					server := httptest.NewServer(router)
					t.Cleanup(server.Close)
					address = server.URL
				} else {
					app := fiber.New()
					noError(t, authkitfiber.Mount(app, f.auth))
					ln, err := net.Listen("tcp", "127.0.0.1:0")
					noError(t, err)
					address = "http://" + ln.Addr().String()
					done := make(chan error, 1)
					go func() { done <- app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true}) }()
					t.Cleanup(func() {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						noError(t, app.ShutdownWithContext(ctx))
						noError(t, <-done)
					})
				}
				client := &http.Client{Timeout: 10 * time.Second}
				call := func(method, path, token, body string) response {
					return wire(t, client, method, address+f.auth.APIBase()+path, token, "application/json", body, nil)
				}
				u := f.user(t)
				session := f.signIn(t, u)
				call("GET", "/capabilities", "", "").want(t, 200, "")
				call("GET", "/me", "", "").want(t, 401, "")
				me := call("GET", "/me", session.AccessToken, "")
				me.want(t, 200, "")
				if !bytes.Contains(me.body, []byte(u.ID)) {
					t.Fatal("adapter lost caller identity")
				}
				call("POST", "/verify/confirm", "not-a-token", `{}`).want(t, 401, "")
				call("POST", "/verify/confirm", "", `{"code":"invalid"}`).want(t, 400, "")
				call("GET", "/admin/users", session.AccessToken, "").want(t, 403, "")
				clock := testclock.Wall()
				testclock.Use(f.auth, clock.Now)
				clock.Advance(16 * time.Minute)
				call("DELETE", "/me", session.AccessToken, "").want(t, 401, "step_up_required")
				call("PATCH", "/me", session.AccessToken, `{"preferred_language":"en"}`).want(t, 200, "")
				cl, err := f.auth.Verify(t.Context(), session.AccessToken)
				noError(t, err)
				noError(t, f.auth.RevokeSession(t.Context(), iam.SystemIdentity(), u.ID, cl.SessionID))
				call("PATCH", "/me", session.AccessToken, `{"preferred_language":"fr"}`).want(t, 401, "session_revoked")
				call("GET", "/me", session.AccessToken, "").want(t, 200, "") // stateless required gate
			})
		}
	})
	t.Run("AK-J31-C03_base_path_HEAD_and_protocol_OPTIONS_are_confined", func(t *testing.T) {
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.Token.Issuer = "https://example.com/identity"
			c.HTTP.BasePath = "/identity"
			c.HTTP.APIPath = "/service"
			c.AuthorizationServer.Clients = []authkit.OAuthClientConfig{{ID: "browser", RedirectURIs: []string{"https://client.example/callback"}}}
		}))
		client := f.server.Client()
		mux := http.NewServeMux()
		noError(t, f.auth.Mount(mux))
		mounted := httptest.NewServer(mux)
		t.Cleanup(mounted.Close)
		wire(t, mounted.Client(), "GET", mounted.URL+f.auth.APIBase()+"/capabilities", "", "", "", nil).want(t, 200, "")
		if f.auth.APIBase() != "/identity/service/v1" {
			t.Fatal("custom API base was not applied")
		}
		if f.auth.PublicAPIBase() != "https://example.com/identity/service/v1" {
			t.Fatal("public API address lost the declared issuer/base path")
		}
		get := wire(t, client, "GET", f.server.URL+f.auth.APIBase()+"/capabilities", "", "", "", nil)
		get.want(t, 200, "")
		head := wire(t, client, "HEAD", f.server.URL+f.auth.APIBase()+"/capabilities", "", "", "", nil)
		head.want(t, 200, "")
		if len(head.body) != 0 || head.header.Get("Content-Type") != get.header.Get("Content-Type") {
			t.Fatal("HEAD did not retain GET headers with an empty body")
		}
		wire(t, client, "GET", f.server.URL+"/identity/.well-known/jwks.json", "", "", "", nil).want(t, 200, "")
		for _, p := range []string{"/api/v1/capabilities", "/service/v1/capabilities", "/.well-known/jwks.json"} {
			wire(t, client, "GET", f.server.URL+p, "", "", "", nil).want(t, 404, "")
		}
		for _, p := range []string{"token", "revoke", "userinfo"} {
			r := wire(t, client, "OPTIONS", f.server.URL+"/identity/oauth2/"+p, "", "", "", http.Header{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"POST"}})
			r.want(t, 204, "")
			if r.header.Get("Access-Control-Allow-Origin") != "https://client.example" || len(r.body) != 0 {
				t.Fatal("registered protocol preflight lost its allowed origin")
			}
		}
	})
	t.Run("AK-J31-C04_malformed_requests_do_not_change_account_state", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		token := f.signIn(t, u).AccessToken
		client := f.server.Client()
		for _, row := range []struct {
			name, body, content string
			status              int
			code                string
		}{
			{"truncated", `{"preferred_language":`, "application/json", 400, "invalid_request"},
			{"wrong_media", `{"preferred_language":"fr"}`, "text/plain", 415, "unsupported_media_type"},
			{"two_values", `{"preferred_language":"fr"} {}`, "application/json", 400, "invalid_request"},
			{"oversized", `{"preferred_language":"` + strings.Repeat("x", 2<<20) + `"}`, "application/json", 400, "invalid_request"},
		} {
			t.Run(row.name, func(t *testing.T) {
				wire(t, client, "PATCH", f.server.URL+f.auth.APIBase()+"/me", token, row.content, row.body, nil).want(t, row.status, row.code)
			})
		}
		f.call(t, "GET", "/me/personal-access-tokens?limit=not-an-integer", token, nil).want(t, 400, "invalid_request")
		f.call(t, "GET", "/groups/not-a-uuid/members", token, nil).want(t, 403, "")
		got, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if got.PreferredLanguage != nil {
			t.Fatal("rejected body changed the account")
		}
		f.call(t, "PATCH", "/me", token, map[string]string{"preferred_language": "en"}).want(t, 200, "")
	})
	t.Run("AK-J31-C05_cookie_origin_CORS_and_proxy_headers_cannot_grant_trust", func(t *testing.T) {
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.HTTP.RefreshCookie = true
			c.AuthorizationServer.Clients = []authkit.OAuthClientConfig{{ID: "web", RedirectURIs: []string{"https://client.example/callback"}}}
		}))
		f.server.Close()
		f.server = httptest.NewTLSServer(f.auth.Handler())
		t.Cleanup(f.server.Close)
		u := f.user(t)
		body, _ := json.Marshal(map[string]string{"identifier": u.Email, "password": u.Password})
		address := f.server.URL + f.auth.APIBase() + "/password/login"
		for _, h := range []http.Header{{"Origin": {"https://attacker.example"}}, {"Origin": {"null"}}, {"Origin": {f.server.URL}, "Sec-Fetch-Site": {"cross-site"}}, {"Origin": {"https://attacker.example"}, "X-Forwarded-Host": {"attacker.example"}, "X-Forwarded-Proto": {"https"}}} {
			r := wire(t, f.server.Client(), "POST", address, "", "application/json", string(body), h)
			r.want(t, 403, "origin_not_allowed")
			if r.header.Get("Set-Cookie") != "" {
				t.Fatal("rejected origin received a sign-in cookie")
			}
		}
		good := wire(t, f.server.Client(), "POST", address, "", "application/json", string(body), http.Header{"Origin": {f.server.URL}, "Sec-Fetch-Site": {"same-origin"}})
		good.want(t, 200, "")
		var signed signInResult
		decode(t, good.body, &signed)
		if signed.Tokens == nil || signed.Tokens.RefreshToken != nil {
			t.Fatal("cookie transport leaked body refresh credentials")
		}
		cookies := (&http.Response{Header: good.header}).Cookies()
		cookie := ""
		for _, c := range cookies {
			if c.Value != "" && c.MaxAge >= 0 && c.HttpOnly && strings.Contains(c.Name, "authkit_rt") {
				if c.Path != "/" || c.SameSite != http.SameSiteLaxMode {
					t.Fatal("refresh cookie scope/protection changed")
				}
				cookie = c.Name + "=" + c.Value
			}
		}
		if cookie == "" {
			t.Fatal("valid origin received no HttpOnly refresh cookie")
		}
		wire(t, f.server.Client(), "POST", f.server.URL+f.auth.APIBase()+"/token", "", "application/json", `{"grant_type":"refresh_token"}`, http.Header{"Origin": {"https://attacker.example"}, "Cookie": {cookie}}).want(t, 403, "origin_not_allowed")
		wire(t, f.server.Client(), "POST", f.server.URL+f.auth.APIBase()+"/token", "", "application/json", `{"grant_type":"refresh_token"}`, http.Header{"Origin": {f.server.URL}, "Cookie": {cookie}}).want(t, 200, "")
		for _, origin := range []string{"https://client.example", "https://attacker.example"} {
			r := wire(t, f.server.Client(), "OPTIONS", f.server.URL+"/oauth2/token", "", "", "", http.Header{"Origin": {origin}})
			r.want(t, 204, "")
			want := ""
			if origin == "https://client.example" {
				want = origin
			}
			if r.header.Get("Access-Control-Allow-Origin") != want || r.header.Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("OAuth CORS widened browser authority")
			}
		}
		g := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.HTTP.RateLimits = map[string]authkit.RateLimit{"capabilities_read": {Limit: 1, Window: time.Minute}}
		}))
		for i := range 2 {
			r, err := g.requestHeaders(t.Context(), "GET", "/capabilities", "", nil, http.Header{"X-Forwarded-For": {fmt.Sprintf("198.51.100.%d", i+1)}, "CF-Connecting-IP": {fmt.Sprintf("198.51.100.%d", i+1)}})
			noError(t, err)
			if i == 0 {
				r.want(t, 200, "")
			} else {
				r.want(t, 429, "")
			}
		}
	})
	t.Run("AK-J31-C07_external_module_can_build_shipped_public_boundaries", func(t *testing.T) {
		root, err := filepath.Abs("..")
		noError(t, err)
		dir := t.TempDir()
		module := "module criticalconsumer\n\ngo 1.26.6\n\nrequire github.com/open-rails/authkit v0.0.0\nreplace github.com/open-rails/authkit => " + root + "\n"
		noError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(module), 0600))
		// This imports the distribution as a separate consumer module, so it
		// cannot accidentally depend on AuthKit's private internal packages.
		program := `package main
import (
 "net/http"
 "github.com/open-rails/authkit"
 "github.com/open-rails/authkit/auth"
 "github.com/open-rails/authkit/iam"
 "github.com/open-rails/authkit/verify"
 "github.com/open-rails/authkit/keys"
 "github.com/open-rails/authkit/userinfo"
 ag "github.com/open-rails/authkit/adapters/gin"
 af "github.com/open-rails/authkit/adapters/fiber"
)
var _ ag.Surface = (*authkit.Client)(nil)
var _ af.Surface = (*authkit.Client)(nil)
var _ verify.Authority = (*authkit.Client)(nil)
var _ http.Handler = (*http.ServeMux)(nil)
func main(){ _=auth.ErrUnauthenticated; _=iam.UserByID("example"); _=keys.JWKS{}; _=userinfo.User{} }
`
		noError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte(program), 0600))
		cmd := exec.CommandContext(t.Context(), "go", "build", "-mod=mod", "-o", filepath.Join(dir, "consumer"), ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOWORK=off")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("public consumer build: %v\n%s", err, output)
		}
	})
}
