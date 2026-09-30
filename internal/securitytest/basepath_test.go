package securitytest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testhttp"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/provider"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// TestSecurityBasePathConfinesSurface: AuthKit under its issuer's path serves
// every route there and none at the host root; OIDC redirect URIs name the
// callback the mount serves (an API-path link start once named one it never
// served); verifiers reach JWKS from the issuer alone; a BasePath that
// disagrees with the issuer is refused.
func TestSecurityBasePathConfinesSurface(t *testing.T) {
	ctx := context.Background()
	pg := testdb.ScratchPostgres(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	const base = "/tenant/auth"
	iss := server.URL + base
	s := signer()
	src := testkeys.Source(s)
	cfg := authkit.Config{
		Token:        authkit.TokenConfig{Issuer: iss, IssuedAudiences: []string{audience}, ExpectedAudiences: []string{audience}},
		Registration: authkit.RegistrationConfig{NativeUserMode: iam.RegistrationModeOpen, Verification: iam.RegistrationVerificationOptional},
		TwoFactor:    authkit.TwoFactorConfig{Mode: iam.TwoFactorOptional, Methods: []iam.TwoFactorMethod{iam.TwoFactorTOTP}, TOTPSecretKey: bytes.Repeat([]byte{7}, 32)},
		HTTP:         testhttp.HTTP(),
	}
	withApps(&cfg)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { *c = cfg }),
		authtest.WithDeps(func(d *authkit.Deps) {
			d.Postgres, d.KeySource, d.Email, d.SMS = pg.Pool, src, nil, nil
			d.Providers = []provider.Provider{provider.GitHub("gh-client", "gh-secret")}
		}))
	require.NoError(t, auth.Mount(mux))

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(method, path, token string, body any) *http.Response {
		t.Helper()
		var reader io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			reader = bytes.NewReader(raw)
		}
		req, err := http.NewRequest(method, server.URL+path, reader)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	decode := func(resp *http.Response, v any) {
		t.Helper()
		require.NoError(t, json.NewDecoder(resp.Body).Decode(v))
	}

	t.Run("no route escapes the base path", func(t *testing.T) {
		routes := auth.Routes()
		require.NotEmpty(t, routes)
		for _, route := range routes {
			require.Truef(t, strings.HasPrefix(route.Path, base+"/"), "%s %s escapes %s", route.Method, route.Path, base)
		}
		for _, want := range []string{"GET " + base + iam.JWKSPath,
			"GET " + base + "/oidc/{provider}/callback", "POST " + base + "/api/v1/oidc/{provider}/link/start", "GET " + base + "/api/v1/me"} {
			require.Contains(t, patterns(auth), want)
		}
		for _, path := range []string{iam.JWKSPath, "/api/v1/capabilities",
			"/oidc/github/login", "/auth" + iam.JWKSPath, "/tenant" + iam.JWKSPath} {
			require.Equal(t, http.StatusTeapot, call(http.MethodGet, path, "", nil).StatusCode, "%s reached AuthKit outside %s", path, base)
		}
	})

	t.Run("capabilities advertise the mount's paths", func(t *testing.T) {
		resp := call(http.MethodGet, base+"/api/v1/capabilities", "", nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var caps struct {
			Paths map[string]string `json:"paths"`
		}
		decode(resp, &caps)
		require.Equal(t, map[string]string{"api": base + "/api/v1", "oidc": base + "/oidc", "jwks": base + iam.JWKSPath}, caps.Paths)
		require.Equal(t, caps.Paths["api"], auth.APIBase())
	})

	user, err := auth.CreateUser(ctx, iam.NewUser{Email: "basepath@security.test", Username: "basepath", Password: password, EmailVerified: true})
	require.NoError(t, err)
	login := call(http.MethodPost, base+"/api/v1/password/login", "", map[string]string{"identifier": "basepath@security.test", "password": password})
	require.Equal(t, http.StatusOK, login.StatusCode)
	var signedIn struct {
		TokenSet struct {
			AccessToken string `json:"access_token"`
		} `json:"token_set"`
	}
	decode(login, &signedIn)
	session := signedIn.TokenSet

	t.Run("a verifier finds JWKS from the issuer", func(t *testing.T) {
		v := verify.NewVerifier()
		require.NoError(t, v.AddIssuer(iss, []string{audience}, verify.IssuerOptions{JWKSURI: iss + iam.JWKSPath, IsLocal: true}))
		claims, err := v.Verify(ctx, session.AccessToken)
		require.NoError(t, err)
		require.Equal(t, user.ID, claims.UserID)
	})

	callback := iss + "/oidc/github/callback"
	redirectURI := func(t *testing.T, authURL string) string {
		t.Helper()
		u, err := url.Parse(authURL)
		require.NoError(t, err)
		return u.Query().Get("redirect_uri")
	}
	t.Run("browser login redirects to the mounted callback", func(t *testing.T) {
		resp := call(http.MethodGet, base+"/oidc/github/login", "", nil)
		require.Equal(t, http.StatusFound, resp.StatusCode)
		require.Equal(t, callback, redirectURI(t, resp.Header.Get("Location")))
	})
	t.Run("API link start redirects to the mounted callback", func(t *testing.T) {
		resp := call(http.MethodPost, base+"/api/v1/oidc/github/link/start", session.AccessToken, map[string]any{})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var start struct {
			AuthURL string `json:"auth_url"`
		}
		decode(resp, &start)
		require.Equal(t, callback, redirectURI(t, start.AuthURL))
	})

	t.Run("BasePath must match the issuer", func(t *testing.T) {
		// authtest.New fails the test on a refusal, so these build directly.
		for _, path := range []string{"/", "/other", "/tenant", base + "/x", "/tenant/{auth}", "/tenant/../auth"} {
			bad, h := cfg, *cfg.HTTP
			h.BasePath = path
			bad.HTTP = &h
			_, err := authkit.New(ctx, bad, authkit.Deps{Postgres: pg.Pool, KeySource: src})
			require.ErrorContains(t, err, "BasePath", "BasePath %q", path)
		}
		again := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.HTTP.BasePath = base + "/" }))
		require.Equal(t, patterns(auth), patterns(again))
	})
}
