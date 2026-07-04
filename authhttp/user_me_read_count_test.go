package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/password"
	"github.com/stretchr/testify/require"
)

// queryCounter is a pgx.QueryTracer that tallies executions of named sqlc queries
// while armed. sqlc prefixes every statement with a `-- name: <Name> :<kind>`
// comment that survives the schema rewrite, so matching that comment counts a
// query independent of parameters or search_path. Used to prove the round-trip
// dedups in #228/#229 actually removed the repeated reads.
type queryCounter struct {
	mu     sync.Mutex
	armed  bool
	counts map[string]int
	names  []string
}

func newQueryCounter(names ...string) *queryCounter {
	return &queryCounter{counts: map[string]int{}, names: names}
}

func (c *queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.armed {
		return ctx
	}
	for _, name := range c.names {
		if strings.Contains(data.SQL, "-- name: "+name+" :") {
			c.counts[name]++
		}
	}
	return ctx
}

func (c *queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (c *queryCounter) arm() {
	c.mu.Lock()
	c.armed = true
	c.mu.Unlock()
}

func (c *queryCounter) disarm() {
	c.mu.Lock()
	c.armed = false
	c.mu.Unlock()
}

func (c *queryCounter) count(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[name]
}

// newTracedServerTestPool mirrors newServerTestPool but attaches a QueryTracer so
// a test can count query executions. Skips when no test database is configured.
func newTracedServerTestPool(t *testing.T, tracer pgx.QueryTracer) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	config, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	config.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	conn, err := pool.Acquire(context.Background())
	require.NoError(t, err)
	_, err = conn.Exec(context.Background(), `SELECT pg_advisory_lock(638476116)`)
	if err != nil {
		conn.Release()
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(638476116)`)
		conn.Release()
	})
	return pool
}

// GET /me used to fan out into ~15 DB round-trips: Get2FASettings ran three times
// (MFA status + step-up methods + step-up 2FA options), the user row was loaded
// twice (AdminGetUser + a re-fetch just for the email), plus a standalone
// preferred-language read. #228 threads a single Get2FASettings + a single user
// row through the whole handler. This asserts the 2FA-settings read now happens
// at most once for the request, while preserving the response shape.
func TestUserMeGET_DeduplicatesProfileAnd2FAReads(t *testing.T) {
	counter := newQueryCounter("MFASettingsByUser", "UserByID", "UserPreferredLanguage")
	pool := newTracedServerTestPool(t, counter)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	srv, err := NewServer(newServerClient(t, cfg, pool), WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("me-readcount")
	username := "mereadcount" + uniqueSuffix()
	const pass = "Correct-password-12345"
	user, err := srv.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))

	// Issue the session + token BEFORE enrolling 2FA: with the default Optional
	// policy, minting a password-only session for an already-enrolled user is
	// gated (enroll first), so the working order mirrors the other step-up tests.
	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	token, _, err := srv.svc.MintAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)

	// An enabled EMAIL second factor exercises the exact branch #228 collapsed:
	// step-up 2FA options previously re-read Get2FASettings AND re-fetched the user
	// row just to obfuscate the email destination.
	_, err = srv.svc.Enable2FA(ctx, user.ID, "email", nil)
	require.NoError(t, err)
	require.NoError(t, srv.svc.SetPreferredLanguage(ctx, user.ID, "en"))

	counter.arm()
	w := serveAuthJSON(srv, http.MethodGet, "/me", `{}`, token)
	counter.disarm()
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// Response shape preserved end-to-end.
	var me struct {
		ID                string                 `json:"id"`
		Email             *string                `json:"email"`
		Username          string                 `json:"username"`
		HasPassword       bool                   `json:"has_password"`
		PreferredLanguage *string                `json:"preferred_language"`
		MFAEnabled        bool                   `json:"mfa_enabled"`
		StepUpMethods     []string               `json:"step_up_methods"`
		StepUp2FA         stepUpOptionsTestShape `json:"step_up_2fa"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &me))
	require.Equal(t, user.ID, me.ID)
	require.Equal(t, username, me.Username)
	require.True(t, me.HasPassword)
	require.True(t, me.MFAEnabled)
	require.NotNil(t, me.PreferredLanguage, "preferred_language must round-trip off the loaded user row")
	require.Equal(t, "en", *me.PreferredLanguage)
	require.Contains(t, me.StepUpMethods, "password")
	require.Contains(t, me.StepUpMethods, "2fa")
	requireStepUp2FAOptions(t, me.StepUp2FA, []string{"email"}, "email")

	// The #228 dedup: the 2FA-settings read (MFASettingsByUser, inside
	// Get2FASettings) now runs exactly once for the whole /me request — it ran
	// three times before. The middleware never reads it, so this count is purely
	// the handler's single, threaded read.
	require.Equal(t, 1, counter.count("MFASettingsByUser"),
		"Get2FASettings must run exactly once for /me (was 3x)")
	// The separate preferred-language read is gone — the value now comes off the
	// widened UserByID projection the handler already loaded.
	require.Equal(t, 0, counter.count("UserPreferredLanguage"),
		"preferred_language must be read off the loaded user row, not a separate query")
	// The user row is loaded at most twice: once by the auth middleware's live-user
	// gate (IsUserAllowed) and once by the handler's AdminGetUser. Before #228 the
	// handler alone loaded it twice (AdminGetUser + the email re-fetch), so 3 total.
	require.LessOrEqual(t, counter.count("UserByID"), 2,
		"the handler must load the user row only once (middleware's gate is the only other read)")
}
