package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/oidckit"
)

// The three GET routes under /oidc are browser navigations: errors must walk
// the user back to the frontend (fragment redirect / popup postMessage /
// step-up return), never strand them on a raw JSON body. These tests pin that
// contract end-to-end through the real router with a registered OAuth2
// provider (no discovery, no DB — every covered failure happens before user
// resolution).

func newBrowserErrorTestService(t *testing.T) (*Service, http.Handler) {
	t.Helper()
	s := newTestService(t)
	var err error
	s.authProvidersByName, err = buildAuthProvidersMap([]authprovider.Provider{
		authprovider.GitHub("github-client", "github-secret"),
	})
	require.NoError(t, err)
	s.resetOIDCManagerForTest()
	return s, s.OIDCHandler()
}

// startBrowserLogin drives GET /oidc/github/login and returns the issued
// state and its browser-binding cookie.
func startBrowserLogin(t *testing.T, h http.Handler, extraQuery string) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	target := "/oidc/github/login"
	if extraQuery != "" {
		target += "?" + extraQuery
	}
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	authURL, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	state := authURL.Query().Get("state")
	require.NotEmpty(t, state)
	var stateCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == oauthStateCookie {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie)
	return state, stateCookie
}

func parseErrorFragment(t *testing.T, w *httptest.ResponseRecorder) url.Values {
	t.Helper()
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	target, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/login/callback", target.Path)
	fragment, err := url.ParseQuery(target.Fragment)
	require.NoError(t, err)
	return fragment
}

// The common real-world failure: the user cancels at the IdP consent screen.
// The callback carries ?error=access_denied and the state; the user must land
// back on the frontend with the code in the fragment — and the one-time state
// must be burned on the way.
func TestBrowserCallback_IdPError_RedirectsToFrontendAndBurnsState(t *testing.T) {
	s, h := newBrowserErrorTestService(t)
	state, cookie := startBrowserLogin(t, h, "return_to=%2Fsubscribe")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/github/callback?error=access_denied&state="+url.QueryEscape(state), nil)
	r.AddCookie(cookie)
	h.ServeHTTP(w, r)

	fragment := parseErrorFragment(t, w)
	require.Equal(t, "access_denied", fragment.Get("error"))
	require.Equal(t, "github", fragment.Get("provider"))
	require.Equal(t, "login", fragment.Get("flow"))
	require.Equal(t, "/subscribe", fragment.Get("return_to"))
	require.Empty(t, fragment.Get("access_token"))

	// The state was consumed on the error path: replaying it (now with a code)
	// is invalid_state, not a resumable flow.
	_, ok, err := s.stateCache().Get(context.Background(), state)
	require.NoError(t, err)
	require.False(t, ok, "error-path callback must burn the one-time state")
}

// A junk/oversize IdP error value must not be reflected; it collapses to the
// stable provider_error code.
func TestBrowserCallback_IdPError_SanitizesReflectedCode(t *testing.T) {
	_, h := newBrowserErrorTestService(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/github/callback?error="+url.QueryEscape("<script>alert(1)</script>"), nil)
	h.ServeHTTP(w, r)

	fragment := parseErrorFragment(t, w)
	require.Equal(t, "provider_error", fragment.Get("error"))
}

func TestSanitizeProviderErrorCode(t *testing.T) {
	cases := map[string]ErrorCode{
		"access_denied":         "access_denied",
		"ACCESS_DENIED":         "access_denied",
		" invalid_scope ":       "invalid_scope",
		"temporarily-down.v2":   "temporarily-down.v2",
		"":                      ErrProviderError,
		"<script>":              ErrProviderError,
		"two words":             ErrProviderError,
		strings.Repeat("a", 65): ErrProviderError,
	}
	for in, want := range cases {
		require.Equal(t, want, sanitizeProviderErrorCode(in), "input %q", in)
	}
}

// Popup flows must resolve the opener immediately: the error comes back as an
// AUTHKIT_OIDC_ERROR postMessage document (distinct from the success type so
// legacy openers ignore it rather than misread it), carrying the popup nonce.
func TestBrowserCallback_PopupFlow_EmitsErrorPostMessage(t *testing.T) {
	_, h := newBrowserErrorTestService(t)
	state, cookie := startBrowserLogin(t, h, "ui=popup&popup_nonce=nonce-123")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/github/callback?error=access_denied&state="+url.QueryEscape(state), nil)
	r.AddCookie(cookie)
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Header().Get("Content-Type"), "text/html")
	require.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
	body := w.Body.String()
	require.Contains(t, body, `"type":"AUTHKIT_OIDC_ERROR"`)
	require.Contains(t, body, `"error":"access_denied"`)
	require.Contains(t, body, `"nonce":"nonce-123"`)
	require.Contains(t, body, `"https://example.com"`) // postMessage target origin from Frontend.BaseURL
	require.NotContains(t, body, "AUTHKIT_OIDC_RESULT")
}

// Step-up flows already own a return path; errors reuse it (?step_up=failed)
// instead of the login fragment.
func TestBrowserCallback_StepUpFlow_RedirectsStepUpFailed(t *testing.T) {
	s, h := newBrowserErrorTestService(t)

	state := "step-up-state-1"
	require.NoError(t, s.stateCache().Put(context.Background(), state, oidckit.StateData{
		Provider:        "github",
		StepUpUserID:    "user-1",
		StepUpSessionID: "sess-1",
		StepUpReturnTo:  "/account/security",
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/github/step-up/callback?error=access_denied&state="+url.QueryEscape(state), nil)
	r.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: state})
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	target, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/account/security", target.Path)
	require.Equal(t, "failed", target.Query().Get("step_up"))
}

// Link flows mark the fragment so the frontend can route the error back to
// the account-linking UI (including popup-window link flows).
func TestBrowserCallback_LinkFlow_MarksFlowLink(t *testing.T) {
	s, h := newBrowserErrorTestService(t)

	state := "link-state-1"
	require.NoError(t, s.stateCache().Put(context.Background(), state, oidckit.StateData{
		Provider:   "github",
		LinkUserID: "user-1",
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/github/callback?error=access_denied&state="+url.QueryEscape(state), nil)
	r.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: state})
	h.ServeHTTP(w, r)

	fragment := parseErrorFragment(t, w)
	require.Equal(t, "access_denied", fragment.Get("error"))
	require.Equal(t, "link", fragment.Get("flow"))
}

// A mismatched/absent state cookie means this browser did not start the flow:
// no context is recovered (and no state consumed) — the generic login
// fragment is used.
func TestBrowserCallback_IdPError_NoCookie_NoContextRecovery(t *testing.T) {
	s, h := newBrowserErrorTestService(t)

	state := "foreign-state-1"
	require.NoError(t, s.stateCache().Put(context.Background(), state, oidckit.StateData{
		Provider:   "github",
		LinkUserID: "user-1",
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/github/callback?error=access_denied&state="+url.QueryEscape(state), nil)
	h.ServeHTTP(w, r) // no cookie

	fragment := parseErrorFragment(t, w)
	require.Equal(t, "login", fragment.Get("flow"), "foreign state must not leak flow context")

	_, ok, err := s.stateCache().Get(context.Background(), state)
	require.NoError(t, err)
	require.True(t, ok, "foreign state must not be consumed by a cookieless caller")
}

// Unknown provider on the login start is a plain navigation, so it also walks
// back to the frontend.
func TestBrowserLoginStart_UnknownProvider_RedirectsToFrontendError(t *testing.T) {
	_, h := newBrowserErrorTestService(t)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oidc/nope/login", nil))

	fragment := parseErrorFragment(t, w)
	require.Equal(t, "oidc_begin_failed", fragment.Get("error"))
	require.Equal(t, "nope", fragment.Get("provider"))
}

// JSON negotiation (Accept: application/json or format=json) keeps the legacy
// envelope on every stage, including the IdP-error echo — sanitized.
func TestBrowserCallback_JSONNegotiation_KeepsEnvelope(t *testing.T) {
	_, h := newBrowserErrorTestService(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/github/callback?error=access_denied", nil)
	r.Header.Set("Accept", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"access_denied"`)

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/oidc/github/callback?format=json", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"invalid_request"`)
}

// 2FA-enrollment-required is a browser outcome too: the enrollment token rides
// the fragment as enrollment_token — deliberately NOT access_token, so a
// frontend that only stores access_token treats the login as failed instead of
// adopting an enrollment-scoped token as a session.
func TestBrowser2FAEnrollmentRequired_FragmentContract(t *testing.T) {
	s := newTestService(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/google/callback", nil)
	s.browser2FAEnrollmentRequired(w, r, "user-1", "google", oidckit.StateData{ReturnTo: "/account"})

	fragment := parseErrorFragment(t, w)
	require.Equal(t, "2fa_enrollment_required", fragment.Get("error"))
	require.Equal(t, "google", fragment.Get("provider"))
	require.NotEmpty(t, fragment.Get("enrollment_token"))
	require.NotEmpty(t, fragment.Get("enrollment_expires_in"))
	require.Equal(t, "/account", fragment.Get("return_to"))
	require.Empty(t, fragment.Get("access_token"), "enrollment token must not masquerade as a session token")

	// JSON negotiation still returns the legacy enrollment envelope.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/oidc/google/callback", nil)
	r.Header.Set("Accept", "application/json")
	s.browser2FAEnrollmentRequired(w, r, "user-1", "google", oidckit.StateData{})
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "2fa_enrollment_required")
	require.Contains(t, w.Body.String(), "access_token")
}

// Popup-context start failures (before any state exists) still resolve the
// opener via postMessage using the request's own ui/popup_nonce markers.
func TestBrowserLoginStart_PopupError_EmitsPostMessage(t *testing.T) {
	_, h := newBrowserErrorTestService(t)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oidc/nope/login?ui=popup&popup_nonce=n-9", nil))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := w.Body.String()
	require.Contains(t, body, `"type":"AUTHKIT_OIDC_ERROR"`)
	require.Contains(t, body, `"nonce":"n-9"`)
}
