package authhttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestCookieSessionBoundaries(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := refreshCookieTestConfig()
	cfg.Registration.PasswordlessLogin = true
	cfg.Registration.PasswordlessAutoRegistration = true
	sender := &captureEmailSender{}
	core := newServerClient(t, cfg, pg.Pool, withEmailSender(sender), withRedis(testdb.ScratchRedis(t)))
	srv, err := newServer(core, WithoutRateLimiter())
	require.NoError(t, err)
	defer srv.Close()
	for _, cookieMode := range []bool{false, true} {
		calls := 0
		h, err := MountHandler(srv, MountOptions{RefreshCookie: cookieMode, Wrap: func(spec RouteSpec, next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(http.StatusNoContent) })
		}})
		require.NoError(t, err)
		for _, tc := range []struct {
			name, media, origin, fetch string
			allowed                    bool
		}{
			{"same-origin JSON", "application/json", cookieTestOrigin, "same-origin", true},
			{"JSON charset", "application/json; charset=utf-8", cookieTestOrigin, "same-origin", true},
			{"native JSON no origin", "application/json", "", "", true},
			{"cross-origin JSON", "application/json", "https://other.example", "cross-site", !cookieMode},
			{"opaque origin", "application/json", "null", "", !cookieMode},
			{"missing cross-site origin", "application/json", "", "cross-site", !cookieMode},
			{"same-site sibling", "application/json", "https://sibling.example.com", "same-site", !cookieMode},
			{"wrong scheme", "application/json", "http://example.com", "", !cookieMode},
			{"origin userinfo", "application/json", "https://user@example.com", "", !cookieMode},
			{"form text", "text/plain", cookieTestOrigin, "same-origin", false},
			{"form encoded", "application/x-www-form-urlencoded", cookieTestOrigin, "same-origin", false},
			{"form multipart", "multipart/form-data; boundary=fixture", cookieTestOrigin, "same-origin", false},
			{"missing media", "", cookieTestOrigin, "same-origin", false},
		} {
			t.Run(fmt.Sprintf("cookies=%v/%s", cookieMode, tc.name), func(t *testing.T) {
				before := calls
				r := httptest.NewRequest(http.MethodPost, "/api/v1/password/login", strings.NewReader(`{}`))
				r.Header.Set("Content-Type", tc.media)
				r.Header.Set("Origin", tc.origin)
				r.Header.Set("Sec-Fetch-Site", tc.fetch)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if tc.allowed {
					require.Equal(t, http.StatusNoContent, w.Code)
					require.Equal(t, before+1, calls)
				} else {
					require.Equal(t, http.StatusBadRequest, w.Code)
					require.Equal(t, before, calls, "guard must run before wrapped handler")
				}
			})
		}
	}

	// Rejected cookie requests must leave one-time credentials usable.
	h, err := MountHandler(srv, MountOptions{RefreshCookie: true})
	require.NoError(t, err)
	email := "cookie-confirm@example.test"
	start := postCookieJSON(h, "/api/v1/passwordless/start", `{"identifier":"`+email+`","mode":"code"}`)
	require.Equal(t, http.StatusAccepted, start.Code, start.Body.String())
	body := `{"identifier":"` + email + `","code":"` + sender.verificationCode(t) + `"}`
	rejected := postCookieJSON(h, "/api/v1/passwordless/confirm", body, func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") })
	require.Equal(t, http.StatusBadRequest, rejected.Code)
	require.Empty(t, rejected.Header().Values("Set-Cookie"))
	accepted := postCookieJSON(h, "/api/v1/passwordless/confirm", body)
	require.Equal(t, http.StatusOK, accepted.Code, accepted.Body.String())
	cookie := refreshCookieOf(t, accepted)
	require.NotNil(t, cookie, "same one-time code remains usable after rejection")
	require.True(t, cookie.HttpOnly)
	require.True(t, cookie.Secure)
	require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	require.Equal(t, "/api/v1/token", cookie.Path)
	var cookieTokens passwordlessTokenBody
	require.NoError(t, json.Unmarshal(accepted.Body.Bytes(), &cookieTokens))
	require.NotEmpty(t, cookieTokens.AccessToken)
	require.Empty(t, cookieTokens.RefreshToken)
	refresh := postCookieJSON(h, "/api/v1/token", `{"grant_type":"refresh_token"}`, func(r *http.Request) { r.AddCookie(cookie) })
	require.Equal(t, http.StatusOK, refresh.Code, refresh.Body.String())
	require.Empty(t, bodyRefreshToken(t, refresh))
	rotated := refreshCookieOf(t, refresh)
	require.NotNil(t, rotated)
	require.NotEqual(t, cookie.Value, rotated.Value)
	var access struct {
		Token string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(refresh.Body.Bytes(), &access))
	logoutRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/logout", nil)
	logoutRequest.Header.Set("Authorization", "Bearer "+access.Token)
	logoutRequest.Header.Set("Origin", cookieTestOrigin)
	logout := httptest.NewRecorder()
	h.ServeHTTP(logout, logoutRequest)
	require.Equal(t, http.StatusNoContent, logout.Code, logout.Body.String())
	cleared := refreshCookieOf(t, logout)
	require.NotNil(t, cleared)
	require.Less(t, cleared.MaxAge, 0)
	require.Equal(t, rotated.Path, cleared.Path)
	require.Equal(t, rotated.HttpOnly, cleared.HttpOnly)
	require.Equal(t, rotated.Secure, cleared.Secure)
	require.Equal(t, rotated.SameSite, cleared.SameSite)
	replay := postCookieJSON(h, "/api/v1/token", `{"grant_type":"refresh_token"}`, func(r *http.Request) { r.AddCookie(rotated) })
	require.Equal(t, http.StatusUnauthorized, replay.Code)

	// The same workflow on a native mount keeps refresh credentials in the body
	// and never consumes browser cookies as a fallback.
	native, err := MountHandler(srv, MountOptions{})
	require.NoError(t, err)
	start = postCookieJSON(native, "/api/v1/passwordless/start", `{"identifier":"`+email+`","mode":"code"}`)
	require.Equal(t, http.StatusAccepted, start.Code, start.Body.String())
	body = `{"identifier":"` + email + `","code":"` + sender.verificationCode(t) + `"}`
	confirmed := postCookieJSON(native, "/api/v1/passwordless/confirm", body)
	require.Equal(t, http.StatusOK, confirmed.Code, confirmed.Body.String())
	var tokens passwordlessTokenBody
	require.NoError(t, json.Unmarshal(confirmed.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.RefreshToken)
	require.Empty(t, confirmed.Header().Values("Set-Cookie"))
	cookieOnly := postCookieJSON(native, "/api/v1/token", `{"grant_type":"refresh_token"}`, func(r *http.Request) { r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: tokens.RefreshToken}) })
	require.Equal(t, http.StatusBadRequest, cookieOnly.Code)
	refreshed := postCookieJSON(native, "/api/v1/token", `{"grant_type":"refresh_token","refresh_token":"`+tokens.RefreshToken+`"}`)
	require.Equal(t, http.StatusOK, refreshed.Code, refreshed.Body.String())
	require.Empty(t, refreshed.Header().Values("Set-Cookie"))

}
