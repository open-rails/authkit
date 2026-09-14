package authhttp

// ak#271 end-to-end through the MOUNTED handler against a real Postgres: the
// full browser lifecycle (sign in -> refresh -> rotate -> logout) with the
// refresh token in an HttpOnly cookie, the OIDC popup + fragment hand-offs, and
// the opt-out mount proving nothing changed for a host that did not ask.
// Skips without AUTHKIT_TEST_DATABASE_URL.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/password"
	"github.com/stretchr/testify/require"
)

const cookieTestOrigin = "https://example.com"

func refreshCookieTestConfig() embedded.Config {
	cfg := newServerTestConfig()
	cfg.Frontend = embedded.FrontendConfig{BaseURL: cookieTestOrigin}
	return cfg
}

// newCookieTestUser creates a password user and returns its id + credentials.
func newCookieTestUser(t *testing.T, pool *pgxpool.Pool, srv *Service, prefix string) (email, pass string) {
	t.Helper()
	ctx := context.Background()
	email = uniqueEmail(prefix)
	pass = "correct-horse-battery-97"
	user, err := srv.svc.CreateUser(ctx, email, prefix+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID)
	})
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))
	return email, pass
}

func postCookieJSON(h http.Handler, path, body string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", cookieTestOrigin)
	r.Host = "example.com"
	for _, m := range mutate {
		m(r)
	}
	h.ServeHTTP(w, r)
	return w
}

func refreshCookieOf(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == RefreshCookieName {
			return c
		}
	}
	return nil
}

func bodyRefreshToken(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	rt, _ := body["refresh_token"].(string)
	return rt
}

// TestRefreshCookie_SourceResolutionAndGates pins the rules that decide whether
// a cookie is honored at all.
func TestRefreshCookie_SourceResolutionAndGates(t *testing.T) {
	pool := testdb.Pool(t)
	srv, err := newServer(newServerClient(t, refreshCookieTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)
	h, err := MountHandler(srv, MountOptions{RefreshCookie: true})
	require.NoError(t, err)

	email, pass := newCookieTestUser(t, pool, srv, "cookiegate")
	login := postCookieJSON(h, "/api/v1/password/login", `{"identifier":"`+email+`","password":"`+pass+`"}`)
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	live := refreshCookieOf(t, login)
	require.NotNil(t, live)

	// Two cookies of the same name fail CLOSED. A sibling host that can set
	// Domain=<parent> plants a value that sorts ahead of the victim's
	// host-only one; r.Cookie would return the attacker's and the session
	// would silently become theirs.
	shadowed := postCookieJSON(h, "/api/v1/token", `{"grant_type":"refresh_token"}`, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: "planted-by-a-sibling-host"})
		r.AddCookie(live)
	})
	require.Equal(t, http.StatusBadRequest, shadowed.Code, "duplicate refresh cookies must be refused")
	// The refusal carries the legacy-path tombstone (see the migration test):
	// an honest jar that holds the pre-v0.98 cookie converges on this very
	// response and the client's retry succeeds; a planted sibling cookie is
	// untouched and stays refused.
	requireLegacyTombstone(t, shadowed)

	// A cross-site Origin is refused, and the session SURVIVES it — a gate
	// failure must never spend or destroy the credential.
	crossSite := postCookieJSON(h, "/api/v1/token", `{"grant_type":"refresh_token"}`, func(r *http.Request) {
		r.Header.Set("Origin", "https://evil.example")
		r.AddCookie(live)
	})
	require.Equal(t, http.StatusBadRequest, crossSite.Code)
	require.Empty(t, crossSite.Header().Get("Set-Cookie"), "a refused gate must not clear the cookie")

	ok := postCookieJSON(h, "/api/v1/token", `{"grant_type":"refresh_token"}`, func(r *http.Request) {
		r.AddCookie(live)
	})
	require.Equal(t, http.StatusOK, ok.Code, "the session must survive the refused cross-site attempt")
	rotated := refreshCookieOf(t, ok)
	require.NotNil(t, rotated)

	// An Origin matching the host the request was ADDRESSED to is same-origin
	// even when it is not the configured Frontend.BaseURL — a deployment reached
	// by an alias, or by 127.0.0.1 while BaseURL says localhost. Caught against
	// a live server: gating on the configured host alone refused every real
	// refresh on the dev stack.
	viaHost := postCookieJSON(h, "/api/v1/token", `{"grant_type":"refresh_token"}`, func(r *http.Request) {
		r.Host = "127.0.0.1:8818"
		r.Header.Set("Origin", "https://127.0.0.1:8818")
		r.AddCookie(rotated)
	})
	require.Equal(t, http.StatusOK, viaHost.Code, viaHost.Body.String())
	rotated = refreshCookieOf(t, viaHost)
	require.NotNil(t, rotated)

	// Body wins over cookie: a client mid-migration still holds the token the
	// server last rotated, and preferring the cookie would spend a credential
	// it does not know was spent. Here the body carries the CURRENT token and
	// the cookie a stale one; honoring the body is what keeps it working.
	bodyWins := postCookieJSON(h, "/api/v1/token",
		`{"grant_type":"refresh_token","refresh_token":"`+rotated.Value+`"}`,
		func(r *http.Request) { r.AddCookie(live) })
	require.Equal(t, http.StatusOK, bodyWins.Code, bodyWins.Body.String())

	// No credential at all is a 400, not a 500 or a silent 200.
	require.Equal(t, http.StatusBadRequest,
		postCookieJSON(h, "/api/v1/token", `{"grant_type":"refresh_token"}`).Code)
}

// TestRefreshCookie_LegacyPathMigration covers the v0.98 Path narrowing
// (<apiPrefix> -> <apiPrefix>/token). A jar that crossed the upgrade holds the
// refresh cookie at BOTH paths and the duplicate gate refuses the pair — the
// contract here is that every cookie-touching response tombstones the legacy
// path, so one refused refresh (or the next login) heals the jar instead of
// bricking the browser.
func TestRefreshCookie_LegacyPathMigration(t *testing.T) {
	pool := testdb.Pool(t)
	srv, err := newServer(newServerClient(t, refreshCookieTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)
	h, err := MountHandler(srv, MountOptions{RefreshCookie: true})
	require.NoError(t, err)

	email, pass := newCookieTestUser(t, pool, srv, "legacypath")
	login := postCookieJSON(h, "/api/v1/password/login", `{"identifier":"`+email+`","password":"`+pass+`"}`)
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	live := refreshCookieOf(t, login)
	require.NotNil(t, live)

	// Session-establishing responses already carry the legacy tombstone, so a
	// migrated jar is healed by the login itself.
	requireLegacyTombstone(t, login)

	// A jar that has not logged in since the upgrade: stale legacy-path value
	// beside the live one. The refresh is refused (fail closed on duplicates)
	// but the refusal tombstones the legacy path.
	stale := postCookieJSON(h, "/api/v1/token", `{"grant_type":"refresh_token"}`, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: "stale-pre-upgrade-ancestor"})
		r.AddCookie(live)
	})
	require.Equal(t, http.StatusBadRequest, stale.Code)
	requireLegacyTombstone(t, stale)

	// After the browser applies that tombstone only the live cookie remains,
	// and the retry succeeds: one refused round trip, not a bricked session.
	retry := postCookieJSON(h, "/api/v1/token", `{"grant_type":"refresh_token"}`, func(r *http.Request) {
		r.AddCookie(live)
	})
	require.Equal(t, http.StatusOK, retry.Code, retry.Body.String())
	requireLegacyTombstone(t, retry)
}

// requireLegacyTombstone asserts the response expires the pre-v0.98 cookie at
// the legacy Path (the API prefix) with attributes matching the old setter.
func requireLegacyTombstone(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, raw := range rec.Header().Values("Set-Cookie") {
		if !strings.HasPrefix(raw, RefreshCookieName+"=") {
			continue
		}
		if strings.Contains(raw, "Path=/api/v1;") || strings.HasSuffix(raw, "Path=/api/v1") {
			require.Contains(t, raw, "Max-Age=0", "legacy-path cookie must be expired, not rewritten: %s", raw)
			return
		}
	}
	t.Fatalf("no legacy-path (Path=/api/v1) tombstone in Set-Cookie: %v", rec.Header().Values("Set-Cookie"))
}

// TestRefreshCookie_OIDCBrowserHandoff covers the two paths that deliver tokens
// to the browser outside a JSON body: the popup document's postMessage payload
// and the redirect URL fragment. Both run against a fake IdP through the
// mounted handler.
func TestRefreshCookie_OIDCBrowserHandoff(t *testing.T) {
	for _, tc := range []struct{ name, ui string }{{"fragment", ""}, {"popup", "popup"}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			pool := testdb.Pool(t)
			srv, err := newServer(newServerClient(t, refreshCookieTestConfig(), pool), WithoutRateLimiter())
			require.NoError(t, err)

			email := uniqueEmail("cookieoidc" + tc.name)
			subject := "cookie-oidc-" + uniqueSuffix()
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email) })

			idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/token":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"access_token": "provider-access-token", "token_type": "Bearer",
					})
				case "/me":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"id": subject, "email": email, "email_verified": true,
						"login": "cookieoidc", "name": "Cookie OIDC",
					})
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(idp.Close)

			setTestProviders(srv, testOAuth2Provider("example-oauth", idp.URL, "oauth-client", "oauth-secret", authprovider.WithScopes("profile", "email")))
			h, err := MountHandler(srv, MountOptions{RefreshCookie: true})
			require.NoError(t, err)

			startPath := "/oidc/example-oauth/login"
			if tc.ui == "popup" {
				startPath += "?ui=popup"
			}
			start := httptest.NewRecorder()
			h.ServeHTTP(start, httptest.NewRequest(http.MethodGet, startPath, nil))
			require.Equal(t, http.StatusFound, start.Code, start.Body.String())
			authURL, err := url.Parse(start.Header().Get("Location"))
			require.NoError(t, err)
			state := authURL.Query().Get("state")
			require.NotEmpty(t, state)
			var stateCookie *http.Cookie
			for _, c := range start.Result().Cookies() {
				if c.Name == stateCookieName(state) {
					stateCookie = c
				}
			}
			require.NotNil(t, stateCookie)

			cb := httptest.NewRecorder()
			cbReq := httptest.NewRequest(http.MethodGet,
				"/oidc/example-oauth/callback?state="+url.QueryEscape(state)+"&code=oauth-code", nil)
			cbReq.AddCookie(stateCookie)
			h.ServeHTTP(cb, cbReq)

			// Whichever hand-off it is, the durable credential rides the
			// cookie and appears nowhere in the script-readable payload.
			c := refreshCookieOf(t, cb)
			require.NotNil(t, c, "the OIDC hand-off must set the refresh cookie")
			require.True(t, c.HttpOnly)
			require.Equal(t, http.SameSiteLaxMode, c.SameSite,
				"Strict would be withheld on the cross-site top-level return from the IdP")

			if tc.ui == "popup" {
				require.Equal(t, http.StatusOK, cb.Code, cb.Body.String())
				doc := cb.Body.String()
				require.Contains(t, doc, "AUTHKIT_OIDC_RESULT")
				require.Contains(t, doc, "access_token")
				require.NotContains(t, doc, "refresh_token",
					"the postMessage payload must not carry the durable credential")
				require.NotContains(t, doc, c.Value)
				return
			}

			require.Equal(t, http.StatusFound, cb.Code, cb.Body.String())
			target, err := url.Parse(cb.Header().Get("Location"))
			require.NoError(t, err)
			frag, err := url.ParseQuery(target.Fragment)
			require.NoError(t, err)
			require.NotEmpty(t, frag.Get("access_token"))
			require.Empty(t, frag.Get("refresh_token"),
				"the redirect fragment must not carry the durable credential")
			require.False(t, strings.Contains(target.Fragment, c.Value))
			require.Equal(t, "no-store", cb.Header().Get("Cache-Control"))
		})
	}
}
