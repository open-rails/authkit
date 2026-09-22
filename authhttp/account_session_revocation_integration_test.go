package authhttp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// Two sites with separate logins share one account store. Account-level
// revocation reaches both issuers; logout and a user's own session management
// stay on the site that served them. Real engines, routes, verifier and PG.
func TestAccountSessionRevocationAcrossIssuers(t *testing.T) {
	queries := &revocationQueryCounter{}
	pool := testdb.PoolWithTracer(t, queries)
	ctx := context.Background()
	suffix := uniqueSuffix()
	issuerA := "https://site-a-" + suffix + ".test"
	issuerB := "https://site-b-" + suffix + ".test"
	issuerC := "https://unlisted-" + suffix + ".test"
	const accessTTL = 4 * time.Second

	site := func(issuer string, ttl time.Duration, accountIssuers ...string) *Service {
		cfg := newServerTestConfig()
		cfg.Token.Issuer = issuer
		cfg.Token.AccountIssuers = accountIssuers
		cfg.Token.AccessTokenDuration = ttl
		cfg.RBAC = []embedded.PersonaDef{embedded.IntrinsicRootPersona(embedded.RoleDef{Name: "operator", Permissions: embedded.IntrinsicRootPermissions()})}
		srv, err := newServer(newServerClient(t, cfg, pool), WithoutRateLimiter())
		require.NoError(t, err)
		t.Cleanup(srv.Close)
		require.True(t, srv.Verifier().HasLiveness(), "authhttp.New supplies the engine liveness source")
		return srv
	}
	siteA := site(issuerA, accessTTL, issuerB)
	siteB := site(issuerB, time.Hour, issuerA, issuerB)
	siteC := site(issuerC, time.Hour)
	require.Equal(t, []string{issuerA, issuerB}, siteA.svc.Config().Token.AccountIssuers)
	require.NoError(t, fixtureBackend(siteA.svc).SeedPermissionGroupContainment(ctx))
	_, err := fixtureBackend(siteA.svc).EnsureRootGroup(ctx)
	require.NoError(t, err)

	type tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		exp          time.Time
	}
	call := func(srv *Service, method, path, bearer, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		srv.apiHandler().ServeHTTP(w, r)
		return w
	}
	login := func(srv *Service, email, pass string) tokens {
		t.Helper()
		w := call(srv, http.MethodPost, "/password/login", "", `{"identifier":"`+email+`","password":"`+pass+`"}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var out tokens
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
		mc, err := srv.verifier.VerifyClaims(ctx, out.AccessToken)
		require.NoError(t, err)
		exp, err := mc.GetExpirationTime()
		require.NoError(t, err)
		out.exp = exp.Time
		return out
	}
	// refresh rotates tok in place and reports the status.
	refresh := func(srv *Service, tok *tokens) int {
		w := call(srv, http.MethodPost, "/token", "", `{"grant_type":"refresh_token","refresh_token":"`+tok.RefreshToken+`"}`)
		if w.Code == http.StatusOK {
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), tok))
		}
		return w.Code
	}
	user := func(tag string) (id, email, pass string) {
		email, pass = newCookieTestUser(t, pool, siteA, tag)
		u, err := siteA.svc.GetUserByEmail(ctx, email)
		require.NoError(t, err)
		return u.ID, email, pass
	}
	victimID, victimEmail, victimPass := user("victim")
	_, bystanderEmail, bystanderPass := user("bystander")
	operatorID, operatorEmail, operatorPass := user("operator")
	require.NoError(t, fixtureBackend(siteA.svc).AssignGroupRoleGenesis(ctx, authkit.RootGroup(), authkit.UserSubject(operatorID), "operator"))

	bystanderA, bystanderB := login(siteA, bystanderEmail, bystanderPass), login(siteB, bystanderEmail, bystanderPass)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	_, err = pool.Exec(ctx, `INSERT INTO user_device_keys (user_id, public_key) VALUES ($1, $2)`, victimID, key)
	require.NoError(t, err)
	victimB, victimC := login(siteB, victimEmail, victimPass), login(siteC, victimEmail, victimPass)
	operator := login(siteA, operatorEmail, operatorPass)
	// Site A's short access TTL starts here; its expiry is asserted below.
	victimA := login(siteA, victimEmail, victimPass)
	w := call(siteA, http.MethodPost, "/admin/users/"+victimID+"/sessions/revoke", operator.AccessToken, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var result authkit.AccountSessionRevocation
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Equal(t, authkit.AccountSessionRevocation{
		Issuers:                []string{issuerA, issuerB},
		RevokedSessions:        map[string]int{issuerA: 1, issuerB: 1},
		RevokedDeviceKeys:      1,
		UnlistedIssuerSessions: 1,
	}, result)

	t.Run("refresh stops on both account issuers", func(t *testing.T) {
		require.Equal(t, http.StatusUnauthorized, refresh(siteA, &victimA))
		require.Equal(t, http.StatusUnauthorized, refresh(siteB, &victimB))
		require.Equal(t, http.StatusOK, refresh(siteC, &victimC), "an unlisted issuer is outside the scope and reported, not silently covered")
	})

	t.Run("another user's sessions remain", func(t *testing.T) {
		require.Equal(t, http.StatusOK, refresh(siteA, &bystanderA))
		require.Equal(t, http.StatusOK, refresh(siteB, &bystanderB))
	})

	t.Run("audit records each session under its issuer", func(t *testing.T) {
		rows, err := pool.Query(ctx, `SELECT issuer, event, session_id, reason FROM session_events
			WHERE user_id=$1 AND event IN ('session_revoked','account_sessions_revoked') ORDER BY id`, victimID)
		require.NoError(t, err)
		defer rows.Close()
		var got []string
		for rows.Next() {
			var issuer, event, sid string
			var reason *string
			require.NoError(t, rows.Scan(&issuer, &event, &sid, &reason))
			require.NotNil(t, reason)
			require.Equal(t, string(embedded.SessionRevokeReasonAdminRevokeAll), *reason)
			require.Equal(t, event == "account_sessions_revoked", sid == "")
			got = append(got, issuer+" "+event)
		}
		require.NoError(t, rows.Err())
		require.ElementsMatch(t, []string{issuerA + " session_revoked", issuerB + " session_revoked", issuerA + " account_sessions_revoked"}, got)
	})

	// Revocation stops token minting. It does not recall issued access tokens:
	// stateless routes accept them until exp, the live gate checks account
	// liveness (ban/deletion), and session-backed step-up fails at once.
	t.Run("issued access token lives until exp; live checks are account-level", func(t *testing.T) {
		live, err := verify.RequiredLive(siteA.verifier)
		require.NoError(t, err)
		probeLive := func() int {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/live", nil)
			req.Header.Set("Authorization", "Bearer "+victimA.AccessToken)
			live(echoClaimsHandler()).ServeHTTP(rec, req)
			return rec.Code
		}
		require.Equal(t, http.StatusOK, call(siteA, http.MethodGet, "/me", victimA.AccessToken, "").Code)
		require.Equal(t, http.StatusOK, probeLive(), "session revocation is not an account-liveness fact")
		stepUp := call(siteA, http.MethodPost, "/step-up/password", victimA.AccessToken, `{"password":"`+victimPass+`"}`)
		require.NotEqual(t, http.StatusOK, stepUp.Code, "a revoked session cannot regain step-up freshness: %s", stepUp.Body.String())

		ban := call(siteA, http.MethodPost, "/admin/users/"+victimID+"/ban", login(siteA, operatorEmail, operatorPass).AccessToken, `{"until":"infinite"}`)
		require.Equal(t, http.StatusNoContent, ban.Code, ban.Body.String())
		require.Equal(t, http.StatusUnauthorized, probeLive(), "ban reaches held access tokens through the live gate immediately")
		// Use the sibling site's hour-long token so the stateless assertion
		// cannot disappear merely because the short site-A token expired.
		request := httptest.NewRequest(http.MethodGet, "/resource", nil)
		request.Header.Set("Authorization", "Bearer "+victimB.AccessToken)
		_, err = siteB.Verifier().VerifyRequest(request)
		require.NoError(t, err, "automatic source wiring must not make stateless verification stateful")
		for _, middleware := range []func(http.Handler) http.Handler{
			verify.Required(siteB.Verifier()), verify.Optional(siteB.Verifier()),
		} {
			before := queries.count.Load()
			response := httptest.NewRecorder()
			middleware(echoClaimsHandler()).ServeHTTP(response, request)
			require.Equal(t, http.StatusOK, response.Code)
			require.Equal(t, before, queries.count.Load(), "ordinary middleware must perform no account lookup")
		}
		beforeLive := queries.count.Load()
		_, err = siteB.Verifier().VerifyRequestLive(request)
		require.Error(t, err, "the default source must deny the banned account")
		require.Greater(t, queries.count.Load(), beforeLive, "the explicit live path must consult the database")
		optionalLive, err := verify.OptionalLive(siteB.Verifier())
		require.NoError(t, err)
		optionalHandler := optionalLive(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		beforeAnonymous := queries.count.Load()
		anonymous := httptest.NewRecorder()
		optionalHandler.ServeHTTP(anonymous, httptest.NewRequest(http.MethodGet, "/public", nil))
		require.Equal(t, http.StatusOK, anonymous.Code)
		require.Equal(t, beforeAnonymous, queries.count.Load(), "anonymous OptionalLive must perform no lookup")
		banned := httptest.NewRecorder()
		optionalHandler.ServeHTTP(banned, request)
		require.Equal(t, http.StatusUnauthorized, banned.Code, "OptionalLive must reject presented banned credentials")
		if time.Now().Before(victimA.exp) {
			require.Equal(t, http.StatusOK, call(siteA, http.MethodGet, "/me", victimA.AccessToken, "").Code, "stateless routes still accept it before exp")
		}
		require.Eventually(t, func() bool {
			return call(siteA, http.MethodGet, "/me", victimA.AccessToken, "").Code == http.StatusUnauthorized
		}, accessTTL+15*time.Second, 250*time.Millisecond)
		require.False(t, time.Now().Before(victimA.exp), "rejected only after the token's own exp")
	})

	t.Run("logout and own session management stay on their issuer", func(t *testing.T) {
		second := login(siteA, bystanderEmail, bystanderPass)
		require.Equal(t, http.StatusNoContent, call(siteA, http.MethodDelete, "/logout", second.AccessToken, "").Code)
		require.Equal(t, http.StatusUnauthorized, refresh(siteA, &second))
		require.Equal(t, http.StatusOK, refresh(siteA, &bystanderA))
		require.Equal(t, http.StatusOK, refresh(siteB, &bystanderB))

		require.Equal(t, http.StatusNoContent, call(siteB, http.MethodDelete, "/user/sessions", bystanderB.AccessToken, "").Code)
		require.Equal(t, http.StatusUnauthorized, refresh(siteB, &bystanderB))
		require.Equal(t, http.StatusOK, refresh(siteA, &bystanderA))
	})

	t.Run("password change keeps the current session and revokes the sibling issuer", func(t *testing.T) {
		current := login(siteB, bystanderEmail, bystanderPass)
		w := call(siteB, http.MethodPost, "/user/password", current.AccessToken, `{"current_password":"`+bystanderPass+`","new_password":"Another-horse-battery-98"}`)
		require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, w.Code, w.Body.String())
		require.Equal(t, http.StatusOK, refresh(siteB, &current))
		require.Equal(t, http.StatusUnauthorized, refresh(siteA, &bystanderA))
	})

	t.Run("ban revokes sibling sessions so unban cannot revive them", func(t *testing.T) {
		id, email, pass := user("banned")
		onB := login(siteB, email, pass)
		require.NoError(t, siteA.svc.BanUser(ctx, id, nil, nil, operatorID))
		require.NoError(t, siteA.svc.UnbanUser(ctx, id))
		require.Equal(t, http.StatusUnauthorized, refresh(siteB, &onB))
	})

	t.Run("unconfigured deployment covers only its own issuer", func(t *testing.T) {
		id, email, pass := user("solo")
		onB, onC := login(siteB, email, pass), login(siteC, email, pass)
		got, err := siteC.svc.AdminRevokeAccountSessions(ctx, id)
		require.NoError(t, err)
		require.Equal(t, []string{issuerC}, got.Issuers)
		require.Equal(t, map[string]int{issuerC: 1}, got.RevokedSessions)
		require.Equal(t, 1, got.UnlistedIssuerSessions)
		require.Equal(t, http.StatusUnauthorized, refresh(siteC, &onC))
		require.Equal(t, http.StatusOK, refresh(siteB, &onB))

		_, err = siteC.svc.AdminRevokeAccountSessions(ctx, "00000000-0000-7000-8000-000000000000")
		require.ErrorIs(t, err, authkit.ErrUserNotFound)
	})
	t.Run("permissions stay live while native bans follow token lifetime", func(t *testing.T) {
		elevated := login(siteB, operatorEmail, operatorPass)
		require.Equal(t, http.StatusOK, call(siteB, http.MethodGet, "/admin/users", elevated.AccessToken, "").Code)
		targetID, _, _ := user("sensitive-target")
		require.NoError(t, siteA.svc.BanUser(ctx, operatorID, nil, nil, operatorID))
		directory := call(siteB, http.MethodGet, "/admin/users", elevated.AccessToken, "")
		require.Equal(t, http.StatusOK, directory.Code, directory.Body.String())
		mutation := call(siteB, http.MethodPost, "/admin/users/"+targetID+"/ban", elevated.AccessToken, `{"until":"infinite"}`)
		require.Equal(t, http.StatusNoContent, mutation.Code, mutation.Body.String())
		target, err := siteB.svc.AdminGetUser(ctx, targetID)
		require.NoError(t, err)
		require.NotNil(t, target.BannedAt, "the existing native identity still has its current permission")
		require.Equal(t, http.StatusUnauthorized, refresh(siteB, &elevated), "ban prevents issuing another access token")
		relogin := call(siteB, http.MethodPost, "/password/login", "", `{"identifier":"`+operatorEmail+`","password":"`+operatorPass+`"}`)
		require.Equal(t, http.StatusUnauthorized, relogin.Code, relogin.Body.String())
		require.NoError(t, siteA.svc.OperatorUnassignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(operatorID), "operator"))
		revoked := call(siteB, http.MethodGet, "/admin/users", elevated.AccessToken, "")
		require.Equal(t, http.StatusForbidden, revoked.Code, revoked.Body.String())
		require.NoError(t, siteA.svc.OperatorAssignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(operatorID), "operator"))
		// The same credential remains valid on ordinary application routes.
		before := queries.count.Load()
		request := httptest.NewRequest(http.MethodGet, "/ordinary", nil)
		request.Header.Set("Authorization", "Bearer "+elevated.AccessToken)
		response := httptest.NewRecorder()
		verify.Required(siteB.Verifier())(echoClaimsHandler()).ServeHTTP(response, request)
		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, before, queries.count.Load())
		require.NoError(t, siteA.svc.UnbanUser(ctx, operatorID))
		// Permission checks do not silently depend on an optional ban backend.
		siteB.Verifier().WithLiveness(nil)
		unavailable := call(siteB, http.MethodGet, "/admin/users", elevated.AccessToken, "")
		require.Equal(t, http.StatusOK, unavailable.Code, unavailable.Body.String())
		siteB.Verifier().WithLiveness(siteB.svc)
		require.NoError(t, siteA.svc.SoftDeleteUser(ctx, operatorID))
		deleted := call(siteB, http.MethodGet, "/admin/users", elevated.AccessToken, "")
		require.Equal(t, http.StatusForbidden, deleted.Code, "deleted identities have no current permission authority")
		latent, err := siteB.svc.ListEffectivePermissions(ctx, authkit.UserSubject(operatorID), authkit.RootGroup())
		require.NoError(t, err)
		require.NotEmpty(t, latent, "introspection and no-escalation checks retain latent assigned grants")
	})

	t.Run("host may replace the default liveness source", func(t *testing.T) {
		verifier := siteC.Verifier().WithLiveness(nil)
		require.False(t, verifier.HasLiveness())
		_, err := verify.RequiredLive(verifier)
		require.ErrorIs(t, err, verify.ErrLivenessUnconfigured)
		verifier.WithLiveness(siteA.svc)
		require.True(t, verifier.HasLiveness())
		_, err = verify.RequiredLive(verifier)
		require.NoError(t, err)
	})

}

// Count real database queries through the production engine's cloned pool.
type revocationQueryCounter struct{ count atomic.Int64 }

func (q *revocationQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	q.count.Add(1)
	return ctx
}
func (*revocationQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
