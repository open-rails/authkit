package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// #294: only OIDC providers (max_age=0 checked against auth_time) are step-up
// methods. An OAuth2 IdP silently re-authorizes an approved app, so completing
// it proves nothing fresh.
func TestStepUpRefusesOAuth2ProvidersAndKeepsOIDC(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 "http://" + r.Host,
				"authorization_endpoint": "http://" + r.Host + "/authorize",
				"token_endpoint":         "http://" + r.Host + "/token",
				"jwks_uri":               "http://" + r.Host + "/jwks",
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)

	setTestProviders(srv,
		authprovider.OIDC("google", idp.URL, "google-client", "google-secret"),
		authprovider.Discord("discord-client", "discord-secret"),
	)

	const pass = "Correct-password-12345"
	userID, staleToken := stalePasswordUserToken(t, srv, pool, "oauth2-stepup", pass)
	require.NoError(t, srv.svc.LinkProviderByIssuer(ctx, userID, idp.URL, "google", "google-sub", nil))
	require.NoError(t, srv.svc.LinkProviderByIssuer(ctx, userID, "https://discord.com", "discord", "discord-sub", nil))

	// The step-up menu (gate metadata and /me) advertises google, never discord.
	w := serveAuthJSON(srv, http.MethodDelete, "/user", `{}`, staleToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	var gate struct {
		Error struct {
			Code     string `json:"code"`
			Metadata struct {
				StepUpMethods []string `json:"step_up_methods"`
			} `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &gate))
	require.Equal(t, "step_up_required", gate.Error.Code)
	require.ElementsMatch(t, []string{"password", "google"}, gate.Error.Metadata.StepUpMethods)

	w = serveAuthJSON(srv, http.MethodGet, "/me", `{}`, staleToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var me struct {
		StepUpMethods []string `json:"step_up_methods"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &me))
	require.ElementsMatch(t, []string{"password", "google"}, me.StepUpMethods)

	w = serveAuthJSON(srv, http.MethodPost, "/oidc/discord/step-up/start", `{}`, staleToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "invalid_method")

	w = serveAuthJSON(srv, http.MethodPost, "/oidc/google/step-up/start", `{"return_to":"/settings"}`, staleToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var start struct {
		AuthURL string `json:"auth_url"`
		State   string `json:"state"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &start))
	require.NotEmpty(t, start.State)
	authURL, err := url.Parse(start.AuthURL)
	require.NoError(t, err)
	require.Equal(t, idp.URL+"/authorize", authURL.Scheme+"://"+authURL.Host+authURL.Path)
	require.Equal(t, "0", authURL.Query().Get("max_age"))
}
