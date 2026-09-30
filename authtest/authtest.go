// Package authtest runs AuthKit in a host's Go tests: a real Client on a
// scratch PostgreSQL schema, an Outbox that captures every email and SMS, an
// identity provider to sign in with (IdP), and helpers for the usual setup (a
// verified user, a signed-in session, a role, an authenticator app, a device
// key, a replica, a stale session).
//
//	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
//		c.Roles = myapp.Roles()
//	}))
//	alice := authtest.NewUser(t, auth)
//	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(alice.ID), myapp.Admin)
//	tokens := authtest.SignIn(t, auth, alice)
//	// call the host's handlers with "Bearer "+tokens.AccessToken, or drive
//	// auth.Handler() and read codes and links from outbox.
//
// New needs AUTHKIT_TEST_DATABASE_URL, a database where the test may create
// schemas. Without it the test is skipped, or fails when
// AUTHKIT_TEST_REQUIRE_DB=1. AUTHKIT_TEST_KEEP_DB=1 keeps each schema.
//
// The package is covered by AuthKit's compatibility contract like the rest of
// the module (docs/stability.md).
package authtest

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/builtwith"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
)

// Issuer and Audience are the token issuer and audience New configures.
const (
	Issuer   = "https://example.com"
	Audience = "authtest"
)

// Option adjusts what New builds.
type Option func(*setup)

type setup struct {
	config []func(*authkit.Config)
	deps   []func(*authkit.Deps)
}

// WithConfig edits the Config New passes to authkit.New, after its defaults.
func WithConfig(fn func(*authkit.Config)) Option {
	return func(s *setup) { s.config = append(s.config, fn) }
}

// WithDeps edits the Deps New passes to authkit.New. The Outbox's senders
// are already Email and SMS; set Postgres to use a pool of your own instead of
// AUTHKIT_TEST_DATABASE_URL.
func WithDeps(fn func(*authkit.Deps)) Option {
	return func(s *setup) { s.deps = append(s.deps, fn) }
}

// New migrates AuthKit into a fresh schema, builds a Client on it, and returns
// the Client with the Outbox wired as its email and SMS senders. The defaults
// differ from a zero Config only where a test needs them to:
//
//   - Token: Issuer and Audience.
//   - TwoFactor.TOTPSecretKey: random, so authenticator apps can enroll.
//   - HTTP: served (DirectPeerIP), without rate limits (Deps.Limiter).
//   - Deps.KeySource: an RSA key generated once per test binary.
//   - Schema and River.Schema: the scratch schema, unless set.
//
// The Client is not started: call Start when a test needs River's work, such
// as Deps.OnEvent or the deletion hooks. Cleanup closes the Client and drops
// the scratch schema.
func New(t testing.TB, opts ...Option) (*authkit.Client, *Outbox) {
	t.Helper()
	var s setup
	for _, opt := range opts {
		opt(&s)
	}
	outbox := &Outbox{}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cfg := authkit.Config{
		Token:     authkit.TokenConfig{Issuer: Issuer, IssuedAudiences: []string{Audience}},
		TwoFactor: authkit.TwoFactorConfig{TOTPSecretKey: key},
		HTTP:      &authkit.HTTPConfig{DirectPeerIP: true},
	}
	deps := authkit.Deps{KeySource: signingKeys(), Email: outbox.Email(), SMS: outbox.SMS(), Limiter: unlimited}
	for _, fn := range s.config {
		fn(&cfg)
	}
	for _, fn := range s.deps {
		fn(&deps)
	}
	ctx := context.Background()
	if deps.Postgres == nil {
		pool, err := pgxpool.New(ctx, testdb.URL(t))
		if err != nil {
			t.Fatalf("authtest: connect: %v", err)
		}
		t.Cleanup(pool.Close)
		deps.Postgres = pool
	}
	if cfg.Schema == "" {
		cfg.Schema = scratchSchema(t, deps.Postgres)
	}
	if cfg.River.Schema == "" {
		cfg.River.Schema = cfg.Schema
	}
	if err := authkit.Migrate(ctx, deps.Postgres, cfg, authkit.MigrateOptions{}); err != nil {
		t.Fatalf("authtest: migrate: %v", err)
	}
	auth, err := authkit.New(ctx, cfg, deps)
	if err != nil {
		t.Fatalf("authtest: new client: %v", err)
	}
	t.Cleanup(auth.Close)
	return auth, outbox
}

// Replica builds another Client on auth's database and schema, as another
// replica of the deployment runs: the Config and Deps auth was built with
// (its Outbox included, when New built it), then opts. auth may be any
// Client authkit.New built, a host's own included. A different Token.Issuer
// makes a sibling deployment sharing the account store; different HTTPConfig
// serves the same accounts another way. HTTP is copied, so opts may set its
// fields; replace, never mutate, the maps and slices opts
// change: the replica shares auth's.
func Replica(t testing.TB, auth *authkit.Client, opts ...Option) *authkit.Client {
	t.Helper()
	cfg, deps := builtWith(t, auth)
	var s setup
	for _, opt := range opts {
		opt(&s)
	}
	if cfg.HTTP != nil {
		h := *cfg.HTTP
		cfg.HTTP = &h
	}
	for _, fn := range s.config {
		fn(&cfg)
	}
	for _, fn := range s.deps {
		fn(&deps)
	}
	replica, err := authkit.New(context.Background(), cfg, deps)
	if err != nil {
		t.Fatalf("authtest: replica: %v", err)
	}
	t.Cleanup(replica.Close)
	return replica
}

// StaleSession moves the sign-in of the session behind accessToken a day into
// the past, as if its user signed in long ago, and returns a new access token
// for that session: routes that need a recent sign-in then ask it for a
// step-up. auth may be any Client authkit.New built.
func StaleSession(t testing.TB, auth *authkit.Client, accessToken string) string {
	t.Helper()
	cfg, deps := builtWith(t, auth)
	schema, err := config.NormalizeSchema(cfg.Schema)
	if err != nil || deps.Postgres == nil {
		t.Fatalf("authtest: stale session: no database (%v)", err)
	}
	ctx := context.Background()
	claims, err := auth.Verify(ctx, accessToken)
	if err != nil || claims.SessionID == "" {
		t.Fatalf("authtest: stale session: no session behind the token (%v)", err)
	}
	tag, err := deps.Postgres.Exec(ctx, `UPDATE `+pgx.Identifier{schema, "refresh_sessions"}.Sanitize()+`
		SET last_authenticated_at = now() - interval '1 day',
		    mfa_authenticated_at = CASE WHEN mfa_authenticated_at IS NULL THEN NULL ELSE now() - interval '1 day' END
		WHERE id = $1::uuid`, claims.SessionID)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("authtest: stale session %s: %v", claims.SessionID, err)
	}
	token, err := auth.MintAccessToken(ctx, claims.UserID, iam.AccessTokenOptions{SessionID: claims.SessionID})
	if err != nil {
		t.Fatalf("authtest: stale session %s: %v", claims.SessionID, err)
	}
	return token.Value
}

// builtWith is the Config and Deps authkit.New built auth with.
func builtWith(t testing.TB, auth *authkit.Client) (authkit.Config, authkit.Deps) {
	t.Helper()
	cfg, deps, ok := builtwith.Of(auth)
	if !ok {
		t.Fatal("authtest: not a Client authkit.New built")
	}
	return cfg, deps
}

var signingKeys = sync.OnceValue(func() keys.Static { return testkeys.Source(testkeys.RSA("authtest")) })

var schemas atomic.Int64

// scratchSchema names a schema no other test uses and drops it at cleanup
// (after the Client closes); Migrate creates it.
func scratchSchema(t testing.TB, pool *pgxpool.Pool) string {
	t.Helper()
	name := fmt.Sprintf("authtest_%d_%s_%d", os.Getpid(), strconv.FormatInt(time.Now().UnixNano(), 36), schemas.Add(1))
	t.Cleanup(func() {
		if os.Getenv("AUTHKIT_TEST_KEEP_DB") != "" {
			t.Logf("authtest: kept schema %s", name)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{name}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("authtest: drop schema %s: %v", name, err)
		}
	})
	return name
}

// unlimited is a rate limiter that allows every request.
func unlimited(string, string) (bool, error) { return true, nil }
