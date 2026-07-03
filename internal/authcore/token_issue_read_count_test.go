package authcore

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// userRowQueryCounter is a pgx QueryTracer that counts how many times specific
// named sqlc queries run, so a test can assert the token-issue path stopped
// re-reading profiles.users (#227). sqlc embeds `-- name: <Query> ...` in the SQL
// text it sends, which the tracer observes verbatim.
type userRowQueryCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func newUserRowQueryCounter() *userRowQueryCounter {
	return &userRowQueryCounter{counts: map[string]int{}}
}

func (c *userRowQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, name := range []string{"UserByID", "UserIsReserved"} {
		if strings.Contains(data.SQL, "name: "+name) {
			c.counts[name]++
		}
	}
	return ctx
}

func (c *userRowQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (c *userRowQueryCounter) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts = map[string]int{}
}

func (c *userRowQueryCounter) get(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[name]
}

// keyedServiceWithTracedPG mirrors keyedServiceWithPG but attaches a pgx query
// tracer to the pool so a test can count the queries a flow issues.
func keyedServiceWithTracedPG(t *testing.T, tr pgx.QueryTracer) *Service {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	cfg.ConnConfig.Tracer = tr
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	// Serialize with the other DB-backed tests via the same advisory lock testPG uses.
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire lock conn: %v", err)
	}
	if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_lock(638476116)`); err != nil {
		conn.Release()
		t.Fatalf("acquire test db lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(638476116)`)
		conn.Release()
	})
	ks := testKeySource(t)
	svc, err := NewFromConfig(Config{
		Token: TokenConfig{
			Issuer:            "https://issuer.test",
			IssuedAudiences:   []string{"app"},
			ExpectedAudiences: []string{"app"},
		},
		Keys: KeysConfig{Source: ks},
	}, pool)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	return svc
}

// TestExchangeRefreshToken_ReadsUserRowAtMostOnce proves the #227 reduction: a single
// refresh now reads the full user row (UserByID) at most once. Before this change the
// same flow read it 3–4× (ensureUserAccessByID, a full-row read for email, the
// IsUserAllowed recheck, and again inside IssueAccessToken).
func TestExchangeRefreshToken_ReadsUserRowAtMostOnce(t *testing.T) {
	counter := newUserRowQueryCounter()
	svc := keyedServiceWithTracedPG(t, counter)
	ctx := context.Background()
	uid := mkRefreshTestUser(t, ctx, svc, "readcount")

	_, rt, _, err := svc.IssueRefreshSession(ctx, uid, "ua", nil)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	counter.reset()
	accessTok, _, newRT, err := svc.ExchangeRefreshToken(ctx, rt, "ua", nil)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if got := counter.get("UserByID"); got > 1 {
		t.Fatalf("ExchangeRefreshToken read the full user row (UserByID) %d× (want ≤1); #227 collapses the pre-fix re-reads into one", got)
	}
	t.Logf("ExchangeRefreshToken profiles.users reads: UserByID=%d UserIsReserved=%d",
		counter.get("UserByID"), counter.get("UserIsReserved"))

	// The rotated token is real and the access token verifies with the right subject.
	if newRT == "" || newRT == rt {
		t.Fatalf("expected a rotated refresh token distinct from the old one")
	}
	if claims := verifyAgainstServiceJWKS(t, svc, accessTok); claims["sub"] != uid {
		t.Fatalf("access token sub = %v, want %v", claims["sub"], uid)
	}
}

// TestTokenIssuePaths_IssueValidTokensAndRejectBanned covers all three issue paths
// touched by #227 — refresh, password login, and 2FA verify — proving they still mint
// valid, verifiable access tokens AND still reject a banned user at the ensureUserAccess
// gate (the security invariant the refactor must preserve).
func TestTokenIssuePaths_IssueValidTokensAndRejectBanned(t *testing.T) {
	svc := keyedServiceWithPG(t)
	ctx := context.Background()

	// --- refresh path ---
	uid := mkRefreshTestUser(t, ctx, svc, "gates-refresh")
	_, rt, _, err := svc.IssueRefreshSession(ctx, uid, "ua", nil)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	accessTok, _, _, err := svc.ExchangeRefreshToken(ctx, rt, "ua", nil)
	if err != nil {
		t.Fatalf("refresh exchange: %v", err)
	}
	if claims := verifyAgainstServiceJWKS(t, svc, accessTok); claims["sub"] != uid {
		t.Fatalf("refresh access token sub = %v, want %v", claims["sub"], uid)
	}

	// --- password-login path (IssueAuthenticatedSession with pwd) ---
	loginUID := mkRefreshTestUser(t, ctx, svc, "gates-login")
	sid, lrt, lTok, _, _, err := svc.IssueAuthenticatedSession(ctx, loginUID, "ua", nil, []string{"pwd"}, nil)
	if err != nil {
		t.Fatalf("login IssueAuthenticatedSession: %v", err)
	}
	if sid == "" || lrt == "" {
		t.Fatalf("login: expected a session id and refresh token")
	}
	lClaims := verifyAgainstServiceJWKS(t, svc, lTok)
	if lClaims["sub"] != loginUID || lClaims["sid"] != sid {
		t.Fatalf("login token: sub=%v sid=%v, want sub=%v sid=%v", lClaims["sub"], lClaims["sid"], loginUID, sid)
	}
	// The login-issued refresh token round-trips, proving a real, active session.
	if _, _, _, err := svc.ExchangeRefreshToken(ctx, lrt, "ua", nil); err != nil {
		t.Fatalf("login refresh token should round-trip through exchange: %v", err)
	}

	// --- 2FA-verify path (IssueAuthenticatedSession with pwd+otp+mfa) ---
	twoUID := mkRefreshTestUser(t, ctx, svc, "gates-2fa")
	sid2, _, tTok, _, _, err := svc.IssueAuthenticatedSession(ctx, twoUID, "ua", nil, []string{"pwd", "otp", "mfa"}, nil)
	if err != nil {
		t.Fatalf("2fa IssueAuthenticatedSession: %v", err)
	}
	tClaims := verifyAgainstServiceJWKS(t, svc, tTok)
	if tClaims["sub"] != twoUID || tClaims["sid"] != sid2 {
		t.Fatalf("2fa token: sub=%v sid=%v, want sub=%v sid=%v", tClaims["sub"], tClaims["sid"], twoUID, sid2)
	}

	// --- banned gate: both refresh and login must reject with ErrUserBanned ---
	bannedUID := mkRefreshTestUser(t, ctx, svc, "gates-banned")
	_, brt, _, err := svc.IssueRefreshSession(ctx, bannedUID, "ua", nil)
	if err != nil {
		t.Fatalf("issue banned-user session: %v", err)
	}
	// Ban WITHOUT going through BanUser (which revokes sessions and would make the
	// refresh fail on the session lookup instead of the user gate), so the
	// ensureUserAccess gate itself is exercised.
	if _, err := svc.pg.Exec(ctx, `UPDATE profiles.users SET banned_at = now() WHERE id = $1::uuid`, bannedUID); err != nil {
		t.Fatalf("ban user: %v", err)
	}
	if _, _, _, err := svc.ExchangeRefreshToken(ctx, brt, "ua", nil); !errors.Is(err, ErrUserBanned) {
		t.Fatalf("banned user refresh: want ErrUserBanned, got %v", err)
	}
	if _, _, _, _, _, err := svc.IssueAuthenticatedSession(ctx, bannedUID, "ua", nil, []string{"pwd"}, nil); !errors.Is(err, ErrUserBanned) {
		t.Fatalf("banned user login: want ErrUserBanned, got %v", err)
	}
}
