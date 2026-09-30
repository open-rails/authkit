package apitest_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/testclock"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/verify"
)

// Session revocation reasons, as internal/authflow records them.
const (
	reasonAdminRevokeAll = "admin_revoke_all"
	reasonRefreshReuse   = "refresh_reuse_detected"
)

// queryCounter counts the database queries a Client issues.
type queryCounter struct{ count atomic.Int64 }

func (q *queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	q.count.Add(1)
	return ctx
}

func (*queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// claimsEcho is a host's protected resource: it answers 200 when the
// middleware in front of it handed it claims.
var claimsEcho = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if _, ok := verify.ClaimsFromContext(r.Context()); !ok {
		http.Error(w, "no claims", http.StatusInternalServerError)
	}
})

// verifiedClaims verifies token with auth and returns its raw claims.
func verifiedClaims(t testing.TB, auth *authkit.Client, token string) map[string]any {
	t.Helper()
	_, err := auth.Verify(t.Context(), token)
	require.NoError(t, err)
	_, claims, ok := jose.Unverified(token)
	require.True(t, ok)
	return claims
}

// refreshSession redeems refreshToken at POST /token, reporting failures
// instead of failing the test, so racing goroutines may call it.
func refreshSession(a *api, refreshToken string) (int, iam.TokenSet, error) {
	res, err := a.send(request{method: http.MethodPost, path: "/token", body: map[string]string{"grant_type": "refresh_token", "refresh_token": refreshToken}})
	if err != nil {
		return 0, iam.TokenSet{}, err
	}
	var tokens iam.TokenSet
	if res.status == http.StatusOK {
		err = json.Unmarshal(res.body, &tokens)
	}
	return res.status, tokens, err
}

// sessionCounts reports the account's live sessions, and its revoked ones
// by reason from its session history.
func sessionCounts(t *testing.T, auth *authkit.Client, userID string) (live int, revoked map[string]int) {
	t.Helper()
	sessions, err := auth.Sessions(t.Context(), userID)
	require.NoError(t, err)
	events, err := auth.ListSessionEvents(t.Context(), userID, iam.SessionEventQuery{Kinds: []iam.SessionEventKind{iam.SessionEventRevoked}})
	require.NoError(t, err)
	revoked = map[string]int{}
	for _, e := range events.Items {
		revoked[e.Reason]++
	}
	return len(sessions), revoked
}

// Two sites with separate logins share one account store. Account-level
// revocation reaches both issuers; logout and a user's own session management
// stay on the site that served them.
func TestAccountSessionRevocationAcrossIssuers(t *testing.T) {
	queries := &queryCounter{}
	ctx := t.Context()
	const (
		issuerA   = "https://site-a.test"
		issuerB   = "https://site-b.test"
		issuerC   = "https://unlisted.test"
		accessTTL = 4 * time.Second
	)
	rbac := authkit.NewRoles()
	var intrinsic []iam.Grant
	for _, perm := range ident.IntrinsicRootPermissions() {
		intrinsic = append(intrinsic, perm)
	}
	staffRole := rbac.Root.Role("staff", intrinsic...)
	auth, outbox := authtest.New(t, authtest.WithDeps(func(d *authkit.Deps) { d.Postgres = testdb.PoolWithTracer(t, queries) }),
		authtest.WithConfig(func(c *authkit.Config) {
			c.Token.Issuer = issuerA
			c.Token.AccountIssuers = []string{issuerB}
			c.Token.AccessTokenDuration = accessTTL
			c.Roles = rbac
			// root:users:manage needs MFA while 2FA is on; this test is about issuers.
			c.TwoFactor.Mode = iam.TwoFactorDisabled
			c.DeviceKeys.Enabled = true
		}))
	type site struct {
		auth *authkit.Client
		api  *api
	}
	siteA := site{auth, newAPI(t, auth)}
	sibling := func(issuer string, accountIssuers ...string) site {
		replica := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) {
			c.Token.Issuer = issuer
			c.Token.AccountIssuers = accountIssuers
			c.Token.AccessTokenDuration = time.Hour
		}))
		return site{replica, newAPI(t, replica)}
	}
	siteB, siteC := sibling(issuerB, issuerA, issuerB), sibling(issuerC)

	type session struct {
		iam.TokenSet
		exp time.Time
	}
	login := func(t *testing.T, s site, u authtest.User) *session {
		t.Helper()
		tokens := authtest.SignIn(t, s.auth, u)
		exp, ok := jose.Time(verifiedClaims(t, s.auth, tokens.AccessToken), "exp")
		require.True(t, ok)
		return &session{TokenSet: tokens, exp: exp}
	}
	// refresh rotates s in place and reports the status.
	refresh := func(t *testing.T, at site, s *session) int {
		t.Helper()
		status, tokens, err := refreshSession(at.api, s.RefreshToken)
		require.NoError(t, err)
		if status == http.StatusOK {
			s.TokenSet = tokens
		}
		return status
	}
	ordinary := func(t *testing.T, middleware func(http.Handler) http.Handler, token string) {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/resource", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		before := queries.count.Load()
		response := httptest.NewRecorder()
		middleware(claimsEcho).ServeHTTP(response, request)
		require.Equal(t, http.StatusOK, response.Code)
		require.Equal(t, before, queries.count.Load(), "ordinary middleware must perform no lookup")
	}
	victim, bystander, staff := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(staff.ID), staffRole)

	bystanderA, bystanderB := login(t, siteA, bystander), login(t, siteB, bystander)
	authtest.EnrollDeviceKey(t, auth, outbox, victim)
	victimB, victimC := login(t, siteB, victim), login(t, siteC, victim)
	staffA := login(t, siteA, staff)
	// Site A's short access TTL starts here; its expiry is asserted below.
	victimA := login(t, siteA, victim)
	res := siteA.api.post("/admin/users/"+victim.ID+"/sessions/revoke", staffA.AccessToken, nil)
	require.Equal(t, http.StatusOK, res.status, res.String())
	var result iam.AccountSessionRevocation
	res.decode(t, &result)
	require.Equal(t, iam.AccountSessionRevocation{
		Issuers:                []string{issuerA, issuerB},
		RevokedSessions:        map[string]int{issuerA: 1, issuerB: 1},
		RevokedDeviceKeys:      1,
		UnlistedIssuerSessions: 1,
	}, result)

	t.Run("refresh stops on both account issuers", func(t *testing.T) {
		require.Equal(t, http.StatusUnauthorized, refresh(t, siteA, victimA))
		require.Equal(t, http.StatusUnauthorized, refresh(t, siteB, victimB))
		require.Equal(t, http.StatusOK, refresh(t, siteC, victimC), "an unlisted issuer is outside the scope and reported, not silently covered")
	})

	t.Run("another user's sessions remain", func(t *testing.T) {
		require.Equal(t, http.StatusOK, refresh(t, siteA, bystanderA))
		require.Equal(t, http.StatusOK, refresh(t, siteB, bystanderB))
	})

	t.Run("audit records each session under its issuer", func(t *testing.T) {
		events, err := auth.ListSessionEvents(ctx, victim.ID, iam.SessionEventQuery{Kinds: []iam.SessionEventKind{iam.SessionEventRevoked, iam.SessionEventAccountSessionsRevoked}})
		require.NoError(t, err)
		var got []string
		for _, e := range events.Items {
			require.Equal(t, reasonAdminRevokeAll, e.Reason)
			require.Equal(t, e.Kind == iam.SessionEventAccountSessionsRevoked, e.SessionID == "")
			got = append(got, e.Issuer+" "+string(e.Kind))
		}
		require.ElementsMatch(t, []string{issuerA + " session_revoked", issuerB + " session_revoked", issuerA + " account_sessions_revoked"}, got)
	})

	// Revocation stops token minting, and every session check refuses the
	// access tokens those sessions minted at once; stateless verification
	// admits them until exp.
	t.Run("session checks refuse held access tokens; stateless routes wait for exp", func(t *testing.T) {
		a := newAPI(t, auth)
		require.Equal(t, http.StatusOK, a.get("/me", victimA.AccessToken).status)
		for _, tc := range []request{
			{method: http.MethodPatch, path: "/user/preferred-language", body: `{"preferred_language":"en"}`},
			{method: http.MethodDelete, path: "/user/sessions"},
			{method: http.MethodPost, path: "/step-up/password", body: map[string]string{"password": victim.Password}},
		} {
			tc.token = victimA.AccessToken
			res := a.do(tc)
			require.Equal(t, http.StatusUnauthorized, res.status, "%s %s: %s", tc.method, tc.path, res)
			require.Contains(t, res.String(), "session_revoked")
		}
		// The sibling site's hour-long token keeps the stateless assertion from
		// passing merely because the short site-A token expired.
		ordinary(t, verify.Required(siteB.auth), victimB.AccessToken)
		ordinary(t, verify.Optional(siteB.auth), victimB.AccessToken)
		if time.Now().Before(victimA.exp) {
			require.Equal(t, http.StatusOK, a.get("/me", victimA.AccessToken).status, "stateless routes still accept it before exp")
		}
		require.Eventually(t, func() bool {
			res, err := a.send(request{method: http.MethodGet, path: "/me", token: victimA.AccessToken})
			return err == nil && res.status == http.StatusUnauthorized
		}, accessTTL+15*time.Second, 250*time.Millisecond)
		require.False(t, time.Now().Before(victimA.exp), "rejected only after the token's own exp")
	})

	t.Run("logout and own session management stay on their issuer", func(t *testing.T) {
		second := login(t, siteA, bystander)
		res := siteA.api.do(request{method: http.MethodDelete, path: "/logout", token: second.AccessToken})
		require.Equal(t, http.StatusNoContent, res.status, res.String())
		require.Equal(t, http.StatusUnauthorized, refresh(t, siteA, second))
		require.Equal(t, http.StatusOK, refresh(t, siteA, bystanderA))
		require.Equal(t, http.StatusOK, refresh(t, siteB, bystanderB))

		res = siteB.api.do(request{method: http.MethodDelete, path: "/user/sessions", token: bystanderB.AccessToken})
		require.Equal(t, http.StatusNoContent, res.status, res.String())
		require.Equal(t, http.StatusUnauthorized, refresh(t, siteB, bystanderB))
		require.Equal(t, http.StatusOK, refresh(t, siteA, bystanderA))
	})

	t.Run("password change keeps the current session and revokes the sibling issuer", func(t *testing.T) {
		current := login(t, siteB, bystander)
		res := siteB.api.post("/user/password", current.AccessToken, map[string]string{"current_password": bystander.Password, "new_password": "Another-horse-battery-98"})
		require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, res.status, res.String())
		require.Equal(t, http.StatusOK, refresh(t, siteB, current))
		require.Equal(t, http.StatusUnauthorized, refresh(t, siteA, bystanderA))
	})

	t.Run("ban revokes sibling sessions so unban cannot revive them", func(t *testing.T) {
		banned := authtest.NewUser(t, auth)
		onB := login(t, siteB, banned)
		require.NoError(t, auth.Ban(ctx, iam.SystemActor(), banned.ID, iam.Ban{}))
		require.NoError(t, auth.Unban(ctx, iam.SystemActor(), banned.ID))
		require.Equal(t, http.StatusUnauthorized, refresh(t, siteB, onB))
	})

	t.Run("unconfigured deployment covers only its own issuer", func(t *testing.T) {
		solo := authtest.NewUser(t, auth)
		onB, onC := login(t, siteB, solo), login(t, siteC, solo)
		got, err := siteC.auth.RevokeAccountSessions(ctx, iam.SystemActor(), solo.ID)
		require.NoError(t, err)
		require.Equal(t, []string{issuerC}, got.Issuers)
		require.Equal(t, map[string]int{issuerC: 1}, got.RevokedSessions)
		require.Equal(t, 1, got.UnlistedIssuerSessions)
		require.Equal(t, http.StatusUnauthorized, refresh(t, siteC, onC))
		require.Equal(t, http.StatusOK, refresh(t, siteB, onB))

		_, err = siteC.auth.RevokeAccountSessions(ctx, iam.SystemActor(), "00000000-0000-7000-8000-000000000000")
		require.ErrorIs(t, err, iam.ErrUserNotFound)
	})

	t.Run("permission gates check the session while native tokens follow their lifetime", func(t *testing.T) {
		b := newAPI(t, siteB.auth)
		directory := func(s *session) response { return b.get("/admin/users", s.AccessToken) }
		elevated := login(t, siteB, staff)
		require.Equal(t, http.StatusOK, directory(elevated).status)
		target := authtest.NewUser(t, auth)
		require.NoError(t, auth.Ban(ctx, iam.SystemActor(), staff.ID, iam.Ban{}))
		res := directory(elevated)
		require.Equal(t, http.StatusUnauthorized, res.status, "a ban ends the sibling issuer's session at once: %s", res)
		res = b.post("/admin/users/"+target.ID+"/ban", elevated.AccessToken, `{"until":"infinite"}`)
		require.Equal(t, http.StatusUnauthorized, res.status, res.String())
		u, err := siteB.auth.User(ctx, iam.UserByID(target.ID))
		require.NoError(t, err)
		require.Nil(t, u.Ban)
		require.Equal(t, http.StatusUnauthorized, refresh(t, siteB, elevated), "ban prevents issuing another access token")
		res = b.post("/password/login", "", map[string]string{"identifier": staff.Email, "password": staff.Password})
		require.Equal(t, http.StatusUnauthorized, res.status, res.String())
		require.NoError(t, auth.Unban(ctx, iam.SystemActor(), staff.ID))
		require.Equal(t, http.StatusUnauthorized, directory(elevated).status, "unban never revives a revoked session")
		elevated = login(t, siteB, staff)
		require.Equal(t, http.StatusOK, directory(elevated).status)
		authtest.RevokeRole(t, auth, iam.RootGroup(), iam.UserSubject(staff.ID), staffRole)
		res = directory(elevated)
		require.Equal(t, http.StatusForbidden, res.status, res.String())
		authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(staff.ID), staffRole)
		// The same credential remains valid on ordinary application routes.
		ordinary(t, verify.Required(siteB.auth), elevated.AccessToken)
		deleted, err := auth.DeleteUsers(ctx, iam.SystemActor(), []string{staff.ID})
		require.NoError(t, err)
		require.NoError(t, deleted[0].Err)
		res = directory(elevated)
		require.Equal(t, http.StatusUnauthorized, res.status, "deletion ends the session: %s", res)
		latent, err := siteB.auth.EffectivePermissions(ctx, iam.UserActor(staff.ID), []iam.GroupRef{iam.RootGroup()})
		require.NoError(t, err)
		require.Empty(t, latent, "a deleted identity acts with no permission")
	})
}

// newGraceClient is a Client with the given refresh-rotation grace on a clock
// the test can advance. The clock follows the wall clock: the rotation time
// the window is measured from is Postgres's.
func newGraceClient(t *testing.T, grace time.Duration) (*authkit.Client, *api, *testclock.Clock) {
	t.Helper()
	clock := testclock.Wall()
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.Token.RefreshRotationGrace = grace }),
		authtest.WithDeps(func(d *authkit.Deps) { d.Clock = clock.Now }))
	return auth, newAPI(t, auth), clock
}

// Replaying a refresh token older than the current one's predecessor revokes
// its family, and only that family.
func TestRefreshFamilyHistory_OldReplayRevokesHTTP(t *testing.T) {
	auth, a, _ := newGraceClient(t, 30*time.Second)
	u := authtest.NewUser(t, auth)
	original := authtest.SignIn(t, auth, u).RefreshToken
	// A different sign-in's family must remain valid for the same user.
	other := authtest.SignIn(t, auth, u).RefreshToken
	current := original
	var predecessor string
	for range 3 {
		status, tokens, err := refreshSession(a, current)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		predecessor, current = current, tokens.RefreshToken
	}
	// Only the immediate predecessor can re-deliver the current token.
	status, tokens, err := refreshSession(a, predecessor)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, current, tokens.RefreshToken)

	status, _, err = refreshSession(a, original)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, status)
	live, revoked := sessionCounts(t, auth, u.ID)
	require.Equal(t, 1, live, "old replay must kill the stolen family, preserving the other sign-in")
	require.Equal(t, map[string]int{reasonRefreshReuse: 1}, revoked)
	status, _, err = refreshSession(a, current)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, status)
	status, _, err = refreshSession(a, other)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
}

// A stale replay racing the current token's rotation revokes the family
// whichever wins.
func TestRefreshFamilyHistory_ReplayRacingRotationHTTP(t *testing.T) {
	auth, a, _ := newGraceClient(t, 30*time.Second)
	u := authtest.NewUser(t, auth)
	original := authtest.SignIn(t, auth, u).RefreshToken
	current := original
	for range 2 {
		status, tokens, err := refreshSession(a, current)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		current = tokens.RefreshToken
	}
	type result struct {
		status int
		tokens iam.TokenSet
		err    error
	}
	start := make(chan struct{})
	replay, rotation := make(chan result, 1), make(chan result, 1)
	for token, out := range map[string]chan result{original: replay, current: rotation} {
		go func() {
			<-start
			status, tokens, err := refreshSession(a, token)
			out <- result{status, tokens, err}
		}()
	}
	close(start)
	replayed, rotated := <-replay, <-rotation
	require.NoError(t, replayed.err)
	require.NoError(t, rotated.err)
	require.Equal(t, http.StatusUnauthorized, replayed.status)
	require.Contains(t, []int{http.StatusOK, http.StatusUnauthorized}, rotated.status)
	live, revoked := sessionCounts(t, auth, u.ID)
	require.Zero(t, live)
	require.Equal(t, map[string]int{reasonRefreshReuse: 1}, revoked)
	if rotated.status == http.StatusOK {
		status, _, err := refreshSession(a, rotated.tokens.RefreshToken)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, status)
	}
}

// The rotation grace window delays reuse detection; it never exempts a
// replay: past the window the replay revokes the family.
func TestRefreshRotationGrace_ExpiredReplayStillRevokes(t *testing.T) {
	t.Run("clock advance", func(t *testing.T) {
		auth, a, clock := newGraceClient(t, 150*time.Millisecond)
		expiredReplayRevokes(t, auth, a, func() { clock.Advance(400 * time.Millisecond) })
	})
	// One wall-clock run keeps the seam honest against the database's own
	// rotation timestamp.
	t.Run("wall clock smoke", func(t *testing.T) {
		auth, a, _ := newGraceClient(t, 20*time.Millisecond)
		expiredReplayRevokes(t, auth, a, func() { time.Sleep(50 * time.Millisecond) })
	})
}

func expiredReplayRevokes(t *testing.T, auth *authkit.Client, a *api, elapse func()) {
	t.Helper()
	u := authtest.NewUser(t, auth)
	token := authtest.SignIn(t, auth, u).RefreshToken
	status, _, err := refreshSession(a, token)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	elapse()
	status, _, err = refreshSession(a, token)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, status)
	live, revoked := sessionCounts(t, auth, u.ID)
	require.Zero(t, live, "a replay past the window must still revoke the family")
	require.Equal(t, map[string]int{reasonRefreshReuse: 1}, revoked)
}

// entitlementsProvider is a billing provider the test changes as it goes.
type entitlementsProvider struct {
	mu    sync.Mutex
	names []string
	err   error
	calls int
}

func (p *entitlementsProvider) ListEntitlements(_ context.Context, users []string) (map[string][]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	return map[string][]string{users[0]: append([]string(nil), p.names...)}, nil
}

func (p *entitlementsProvider) set(names []string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.names, p.err = names, err
}

func (p *entitlementsProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// Token.EntitlementAllowlist selects which of the provider's names native
// access tokens carry, at registration, sign-in, refresh and host mints. The
// allowlist is validated and copied at New; selection never manufactures a
// grant; a provider failure never blocks a session; forged claims never pass;
// the account's own view stays unfiltered.
func TestTokenEntitlementAllowlist(t *testing.T) {
	provider := &entitlementsProvider{names: []string{"premium", "unselected", "product-a", "premium"}}
	auth, _ := authtest.New(t, authtest.WithDeps(func(d *authkit.Deps) { d.Entitlements = provider.ListEntitlements }),
		authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorDisabled }))
	ctx := t.Context()
	claimsOf := func(t *testing.T, auth *authkit.Client, token string) map[string]any {
		t.Helper()
		return verifiedClaims(t, auth, token)
	}
	input := []string{"premium", "lifetime", "premium"}
	selecting := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.Token.EntitlementAllowlist = input }))
	for i := range input {
		input[i] = "changed"
	}

	t.Run("new validates the allowlist", func(t *testing.T) {
		cfg, deps := bareConfig(t)
		tooMany := make([]string, 33)
		for i := range tooMany {
			tooMany[i] = fmt.Sprintf("feature-%d", i)
		}
		// 32 names of 128 bytes each: within the count, over the encoded size.
		tooLarge := make([]string, 32)
		for i := range tooLarge {
			tooLarge[i] = fmt.Sprintf("%02d", i) + strings.Repeat("x", 126)
		}
		for _, bad := range [][]string{{""}, {" premium"}, {strings.Repeat("x", 129)}, {string([]byte{0xff})}, tooMany, tooLarge} {
			cfg.Token.EntitlementAllowlist = bad
			auth, err := newClient(t, cfg, deps)
			require.Error(t, err, "%q", bad)
			require.Nil(t, auth)
		}
	})

	t.Run("registration, sign-in and refresh", func(t *testing.T) {
		a := newAPI(t, auth)
		res := a.post("/register", "", map[string]any{"identifier": "entitlement-policy@example.test", "username": "entpolicy", "password": "Correct-horse-policy-password-1"})
		registered := expectAnswer(t, res, http.StatusAccepted)
		require.NotContains(t, claimsOf(t, auth, registered.tokens().AccessToken), "entitlements")
		require.Zero(t, provider.callCount(), "an empty allowlist must not query billing during registration")

		s := newAPI(t, selecting)
		login := expectAnswer(t, s.post("/password/login", "", map[string]string{"identifier": "entitlement-policy@example.test", "password": "Correct-horse-policy-password-1"}), http.StatusOK).tokens()
		claims := claimsOf(t, selecting, login.AccessToken)
		require.Equal(t, []any{"premium"}, claims["entitlements"])
		for _, key := range []string{"roles", "permissions", "groups", "root_permissions"} {
			require.NotContains(t, claims, key)
		}
		wireGolden(t, "access-claims", claims)
		provider.set([]string{"lifetime", "product-b"}, nil)
		status, refreshed, err := refreshSession(s, login.RefreshToken)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, []any{"lifetime"}, claimsOf(t, selecting, refreshed.AccessToken)["entitlements"])
		provider.set(nil, errors.New("test billing unavailable"))
		status, failed, err := refreshSession(s, refreshed.RefreshToken)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		require.NotContains(t, claimsOf(t, selecting, failed.AccessToken), "entitlements", "provider failure does not become a grant or prevent a session")
	})

	t.Run("host mints", func(t *testing.T) {
		u := authtest.NewUser(t, auth)
		forged := map[string]any{"entitlements": []string{"forged"}, "root_permissions": map[string]any{"grants": []string{"root:*"}},
			"roles": []string{"owner"}, "permissions": []string{"root:*"}}
		mint := func(t *testing.T, auth *authkit.Client) map[string]any {
			t.Helper()
			token, err := auth.MintAccessToken(ctx, u.ID, iam.AccessTokenOptions{Claims: forged})
			require.NoError(t, err)
			claims := claimsOf(t, auth, token.Value)
			for _, key := range []string{"root_permissions", "roles", "permissions"} {
				require.NotContains(t, claims, key)
			}
			return claims
		}
		grants := []string{"premium", "product-1", "premium", "unselected"}
		provider.set(grants, nil)
		before := provider.callCount()
		require.NotContains(t, mint(t, auth), "entitlements")
		require.Equal(t, before, provider.callCount(), "an empty allowlist never queries billing")
		require.Equal(t, []any{"premium"}, mint(t, selecting)["entitlements"])
		var me struct {
			Entitlements []string `json:"entitlements"`
		}
		res := newAPI(t, selecting).get("/me", authtest.SignIn(t, selecting, u).AccessToken)
		require.Equal(t, http.StatusOK, res.status, res.String())
		res.decode(t, &me)
		require.Equal(t, grants, me.Entitlements, "the account's own view remains unfiltered")
		// New deduplicated, sorted and copied the allowlist: the selection
		// comes out in its order, unaffected by the caller's later edit.
		provider.set([]string{"premium", "product-1", "lifetime"}, nil)
		require.Equal(t, []any{"lifetime", "premium"}, mint(t, selecting)["entitlements"])
		provider.set([]string{"product-1"}, nil)
		require.NotContains(t, mint(t, selecting), "entitlements", "an allowlist never manufactures a grant")
		provider.set(nil, errors.New("provider unavailable"))
		require.NotContains(t, mint(t, selecting), "entitlements", "provider failure must not prevent a session or grant claims")
	})
}
