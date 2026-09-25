package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// An unreachable identity provider fails only its own login with 503
// provider_unavailable; genuine client errors keep their statuses, and logins
// recover without a restart once the provider returns.
func TestOIDCProviderOutageIsServiceUnavailable(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	srv, err := newTestService(newServerClient(t, newServerTestConfig(), pool), workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	idp := newFakeOIDCIdP(t, "outage-client")
	subject := "outage-" + uniqueSuffix()
	idp.SetIdentity(subject, uniqueEmail("oidc-outage"), true, nil)
	provider := idp.Provider("custom", authprovider.WithPKCE(true))
	setTestProviders(srv, provider)
	h := srv.oidcHandler()
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id IN (SELECT user_id FROM user_providers WHERE issuer=$1 AND subject=$2)`, idp.Server.URL, subject)
	})
	jsonError := func(w *httptest.ResponseRecorder) (int, string) {
		var env authkit.ErrorEnvelope
		_ = json.Unmarshal(w.Body.Bytes(), &env)
		return w.Code, env.Error.Code
	}
	start := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oidc/custom/login?format=json", nil))
		return w
	}
	callback := func(f oidcFlow) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/oidc/custom/callback?format=json&state="+url.QueryEscape(f.state)+"&code=idp-code", nil)
		for _, c := range f.cookies {
			req.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	health := provider.(authprovider.HealthChecker)

	// Discovery unavailable on first use: 503, not 400.
	idp.outage.Store("503")
	status, code := jsonError(start())
	require.Equal(t, http.StatusServiceUnavailable, status)
	require.Equal(t, string(authkit.CodeProviderUnavailable), code)
	require.ErrorIs(t, health.CheckHealth(ctx), authprovider.ErrProviderUnavailable)

	// Recovery is background; the next login after it simply works.
	idp.outage.Store("")
	require.Eventually(t, func() bool { return health.CheckHealth(ctx) == nil }, 10*time.Second, 20*time.Millisecond)
	require.Equal(t, http.StatusFound, start().Code)

	// Cached discovery keeps logins starting; a token endpoint outage during the
	// exchange is 503, not 401.
	f := startOIDCFlow(t, h, "custom")
	idp.SetNonce(f.nonce)
	idp.outage.Store("reset")
	require.Equal(t, http.StatusFound, start().Code)
	status, code = jsonError(callback(f))
	require.Equal(t, http.StatusServiceUnavailable, status)
	require.Equal(t, string(authkit.CodeProviderUnavailable), code)
	idp.outage.Store("503")
	f = startOIDCFlow(t, h, "custom")
	idp.SetNonce(f.nonce)
	status, code = jsonError(callback(f))
	require.Equal(t, http.StatusServiceUnavailable, status)
	require.Equal(t, string(authkit.CodeProviderUnavailable), code)

	// A genuine rejection from a reachable provider keeps its 401.
	idp.outage.Store("")
	f = startOIDCFlow(t, h, "custom")
	idp.SetNonce("not-" + f.nonce)
	status, code = jsonError(callback(f))
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, string(authkit.CodeOIDCExchangeFailed), code)

	f = startOIDCFlow(t, h, "custom")
	idp.SetNonce(f.nonce)
	idp.ExpectCodeChallenge(f.codeChallenge)
	loc := f.callback(t, h, "custom", f.state)
	require.Contains(t, loc, "access_token", loc)
}
