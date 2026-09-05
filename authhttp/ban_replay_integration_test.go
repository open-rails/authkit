package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// #288/3: banning a user must kill the credentials they already hold, not only
// block new logins — the held refresh token, every session, and (through the
// liveness gate) the held access token. Delegated tokens and API keys are
// deliberately outside this: a delegated token is a TTL-bounded consumer
// credential verified by VerifyDelegatedAccess (verify/liveness.go treats it as
// a non-user principal) and an API key belongs to the permission group, not to
// the user who minted it.
func TestBanRevokesHeldCredentials(t *testing.T) {
	forEachStore(t, testBanRevokesHeldCredentials)
}

func testBanRevokesHeldCredentials(t *testing.T, store ephemeralStore) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	srv, err := newServer(newServerClient(t, newServerTestConfig(), pool, store.engineOpts()...), WithoutRateLimiter())
	require.NoError(t, err)
	email, pass := newCookieTestUser(t, pool, srv, "ban-replay")

	login := serveJSON(srv, http.MethodPost, "/password/login", `{"identifier":"`+email+`","password":"`+pass+`"}`)
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(login.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.RefreshToken)

	srv.verifier.WithLiveness(srv.svc)
	requiredLive, err := verify.RequiredLive(srv.verifier)
	require.NoError(t, err)
	live := requiredLive(echoClaimsHandler())
	probe := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/live", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		live.ServeHTTP(rec, req)
		return rec
	}
	rec := probe()
	require.Equal(t, http.StatusOK, rec.Code, "the access token must pass the liveness gate before the ban: %s", rec.Body.String())

	user, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	reason := "abuse"
	require.NoError(t, srv.svc.BanUser(ctx, user.ID, &reason, nil, user.ID))

	refresh := serveJSON(srv, http.MethodPost, "/token", `{"grant_type":"refresh_token","refresh_token":"`+tokens.RefreshToken+`"}`)
	require.Equal(t, http.StatusUnauthorized, refresh.Code, refresh.Body.String())

	sessions, err := srv.svc.ListUserSessions(ctx, user.ID)
	require.NoError(t, err)
	require.Empty(t, sessions, "a ban revokes every session")

	rec = probe()
	require.Equal(t, http.StatusUnauthorized, rec.Code, "the held access token must be refused by the liveness gate after the ban: %s", rec.Body.String())
}
