package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testdpop"
	"github.com/open-rails/authkit/verify"
)

func ephemeralEngine(t *testing.T) *Engine {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	core, err := New(t.Context(), maintenanceConfig(), config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(func() { _ = core.Close(context.Background()) })
	return core
}

// race starts n callers of fn together and returns how many won.
func race(t *testing.T, n int, fn func() (bool, error)) int {
	t.Helper()
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range n {
		wg.Go(func() {
			<-start
			won, err := fn()
			assert.NoError(t, err)
			if won {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}
	close(start)
	wg.Wait()
	return wins
}

func TestEphemeralSingleUseUnderConcurrency(t *testing.T) {
	kv := ephemeralEngine(t).ephemeral
	ctx := t.Context()
	const callers, rounds = 16, 50
	for round := range rounds {
		key := fmt.Sprintf("consume:%d", round)
		require.NoError(t, kv.Set(ctx, key, []byte("secret"), time.Minute))
		wins := race(t, callers, func() (bool, error) {
			v, ok, err := kv.Consume(ctx, key)
			if ok {
				assert.Equal(t, []byte("secret"), v)
			}
			return ok, err
		})
		require.Equal(t, 1, wins, "round %d", round)

		key = fmt.Sprintf("cas:%d", round)
		require.NoError(t, kv.Set(ctx, key, []byte("current"), time.Minute))
		stale := race(t, callers, func() (bool, error) { return kv.CompareAndConsume(ctx, key, []byte("stale")) })
		require.Zero(t, stale, "a stale value must never claim")
		wins = race(t, callers, func() (bool, error) { return kv.CompareAndConsume(ctx, key, []byte("current")) })
		require.Equal(t, 1, wins, "round %d", round)
		_, ok, err := kv.Get(ctx, key)
		require.NoError(t, err)
		require.False(t, ok)
	}
}

func TestEphemeralIncrIsAtomicAndKeepsItsTTL(t *testing.T) {
	core := ephemeralEngine(t)
	kv, ctx := core.ephemeral, t.Context()
	const callers = 32
	var mu sync.Mutex
	var got []int64
	race(t, callers, func() (bool, error) {
		n, err := kv.Incr(ctx, "attempts", time.Minute)
		mu.Lock()
		got = append(got, n)
		mu.Unlock()
		return true, err
	})
	slices.Sort(got)
	for i, n := range got {
		require.Equal(t, int64(i+1), n)
	}

	expiry := func() time.Time {
		var at time.Time
		require.NoError(t, core.pg.QueryRow(ctx, `SELECT expires_at FROM ephemeral_kv WHERE key = 'attempts'`).Scan(&at))
		return at
	}
	first := expiry()
	_, err := kv.Incr(ctx, "attempts", time.Hour)
	require.NoError(t, err)
	require.Equal(t, first, expiry(), "Incr must not extend the counter's TTL")
	v, ok, err := kv.Get(ctx, "attempts")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, fmt.Sprint(callers+1), string(v))
}

func TestEphemeralExpiry(t *testing.T) {
	core := ephemeralEngine(t)
	kv, ctx := core.ephemeral, t.Context()

	require.NoError(t, kv.Set(ctx, "code", []byte("v"), time.Hour))
	require.NoError(t, kv.Set(ctx, "cas", []byte("v"), time.Hour))
	for range 2 {
		_, err := kv.Incr(ctx, "counter", time.Hour)
		require.NoError(t, err)
	}
	_, err := core.pg.Exec(ctx, `UPDATE ephemeral_kv SET expires_at = now() - interval '1 millisecond'`)
	require.NoError(t, err)

	_, ok, err := kv.Get(ctx, "code")
	require.NoError(t, err)
	require.False(t, ok, "an expired row is missing")
	_, ok, err = kv.Consume(ctx, "code")
	require.NoError(t, err)
	require.False(t, ok)
	claimed, err := kv.CompareAndConsume(ctx, "cas", []byte("v"))
	require.NoError(t, err)
	require.False(t, claimed)
	n, err := kv.Incr(ctx, "counter", time.Hour)
	require.NoError(t, err)
	require.Equal(t, int64(1), n, "an expired counter restarts")

	require.Error(t, kv.Set(ctx, "forever", []byte("v"), 0))
	_, err = kv.Incr(ctx, "forever", -time.Second)
	require.Error(t, err)
}

// A host clock far from the database's never changes what is live.
func TestEphemeralIgnoresHostClock(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	skewed := func() time.Time { return time.Now().Add(24 * time.Hour) }
	core, err := New(t.Context(), maintenanceConfig(), config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(func() { _ = core.Close(context.Background()) })
	core.SetClock(skewed)
	ctx := t.Context()
	require.NoError(t, core.ephemeral.Set(ctx, "proof", []byte("v"), time.Minute))
	_, ok, err := core.ephemeral.Get(ctx, "proof")
	require.NoError(t, err)
	require.True(t, ok)
}

func TestEphemeralSweepPurgesOnlyExpiredRows(t *testing.T) {
	core := ephemeralEngine(t)
	ctx := t.Context()
	_, err := core.pg.Exec(ctx, `INSERT INTO ephemeral_kv (key, value, expires_at)
SELECT 'expired:' || i, '\x00', now() - interval '1 second' FROM generate_series(1, $1::int) i`, 2*ephemeralSweepBatch+5)
	require.NoError(t, err)
	require.NoError(t, core.ephemeral.Set(ctx, "live", []byte("v"), time.Hour))

	n, err := core.purgeExpiredEphemeral(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(2*ephemeralSweepBatch+5), n)
	var rows int
	require.NoError(t, core.pg.QueryRow(ctx, `SELECT count(*) FROM ephemeral_kv`).Scan(&rows))
	require.Equal(t, 1, rows)
	_, ok, err := core.ephemeral.Get(ctx, "live")
	require.NoError(t, err)
	require.True(t, ok)
}

// AuthKit's own River periodic job purges expired rows and leaves live ones.
func TestEphemeralSweepRunsAsRiverMaintenance(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	require.NoError(t, Migrate(t.Context(), pg.Pool, config.DatabaseConfig{}))
	cfg := maintenanceConfig()
	cfg.CleanupInterval = time.Second
	core, err := New(t.Context(), cfg, config.Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(func() { _ = core.Close(context.Background()) })
	ctx := t.Context()
	expire := func(key string) {
		require.NoError(t, core.ephemeral.Set(ctx, key, []byte("v"), time.Hour))
		_, err := pg.Pool.Exec(ctx, `UPDATE profiles.ephemeral_kv SET expires_at = now() - interval '1 second' WHERE key = $1`, key)
		require.NoError(t, err)
	}
	purged := func(key string) func() bool {
		return func() bool {
			var exists bool
			err := pg.Pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM profiles.ephemeral_kv WHERE key = $1)`, key).Scan(&exists)
			return err == nil && !exists
		}
	}
	expire("expired:1")
	require.NoError(t, core.ephemeral.Set(ctx, "live", []byte("v"), time.Hour))
	require.NoError(t, core.Start(ctx, nil))
	require.Eventually(t, purged("expired:1"), 15*time.Second, 25*time.Millisecond)
	// A second purge proves recurring scheduling, not just RunOnStart.
	expire("expired:2")
	require.Eventually(t, purged("expired:2"), 15*time.Second, 25*time.Millisecond)
	_, ok, err := core.ephemeral.Get(ctx, "live")
	require.NoError(t, err)
	require.True(t, ok, "the sweep must leave live rows")
}

// A failing DPoP replay claim is an operational failure, never an invalid
// proof: the delegated mint and a resource verifier answer 500 without a DPoP
// challenge, and once the store is back the same proofs are accepted.
func TestDPoPReplayStoreOutageFailsClosed(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := t.Context()
	cfg := testConfig()
	cfg.Delegated = config.DelegatedConfig{Audiences: []string{"platform"}, AllowDPoP: true}
	cfg.HTTP = &config.HTTPConfig{DirectPeerIP: true}
	deps := config.Deps{Postgres: pg.Pool, KeySource: testKeys(), DelegatedAuthorization: func(context.Context, iam.DelegationRequest) (iam.DelegationGrant, error) {
		return iam.DelegationGrant{Permissions: []string{"resource:read"}}, nil
	}}
	e := newTestEngine(t, cfg, deps)
	srv, err := httpapi.New(e, e.Config(), deps)
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	h, err := httpapi.NewMount(srv)
	require.NoError(t, err)
	user := newUser(t, e, "dpop")
	sid, _, err := e.issueRefreshSession(ctx, user.ID)
	require.NoError(t, err)
	session, _, err := e.mintAccessToken(ctx, user.ID, map[string]any{"sid": sid}, e.cfg.Token.AccessTokenDuration)
	require.NoError(t, err)

	browserKey := testdpop.Key(t)
	target := cfg.Token.Issuer + "/api/v1/delegated/token"
	mint := func(proof string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/delegated/token", strings.NewReader(`{"requested_grant":{}}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+session)
		r.Header.Set("DPoP", proof)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	res := mint(testdpop.Proof(t, browserKey, http.MethodPost, target, session, nil))
	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	var minted iam.TokenSet
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &minted))
	require.Equal(t, "DPoP", minted.TokenType)

	const resource = "https://resource.example"
	v := verify.NewVerifier(verify.WithDPoP(e.ClaimDPoPProof), verify.WithPublicURL(resource))
	require.NoError(t, v.AddIssuer(cfg.Token.Issuer, []string{"platform"}, verify.IssuerOptions{KeySource: deps.KeySource}))
	req := httptest.NewRequest(http.MethodGet, resource+"/tasks", nil)
	req.Header.Set("Authorization", "DPoP "+minted.AccessToken)
	req.Header.Set("DPoP", testdpop.Proof(t, browserKey, http.MethodGet, resource+"/tasks", minted.AccessToken, nil))

	restore := failEphemeral(t, pg.Pool, "INSERT OR UPDATE", "NEW", "dpop:proof:")
	mintProof := testdpop.Proof(t, browserKey, http.MethodPost, target, session, nil)
	res = mint(mintProof)
	require.Equal(t, http.StatusInternalServerError, res.Code, res.Body.String())
	require.Contains(t, res.Body.String(), "internal_error")
	require.Empty(t, res.Header().Get("WWW-Authenticate"))
	_, err = v.VerifyRequest(req)
	require.Error(t, err)
	require.Equal(t, errmodel.CodeInternalError, errmodel.CodeOf(err))
	rejected := httptest.NewRecorder()
	verify.Required(v)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("storage outage admitted request") })).ServeHTTP(rejected, req)
	require.Equal(t, http.StatusInternalServerError, rejected.Code)
	require.Empty(t, rejected.Header().Get("WWW-Authenticate"))

	restore()
	res = mint(mintProof)
	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	cl, err := v.VerifyRequest(req)
	require.NoError(t, err)
	require.NotEmpty(t, cl.JWKThumbprint)
}
