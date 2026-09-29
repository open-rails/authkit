// Package authtest runs AuthKit in a host's Go tests: a real Client on a
// scratch PostgreSQL schema, an Outbox that captures every email and SMS, and
// helpers for the usual setup (a verified user, a signed-in session, a role,
// an authenticator app, a device key).
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
// The package is outside AuthKit's compatibility contract: it may change in
// any minor release.
package authtest

import (
	"context"
	"crypto"
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
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
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

// WithDeps edits the Deps New passes to authkit.New. The Outbox is already
// Email and SMS; set Postgres to use a pool of your own instead of
// AUTHKIT_TEST_DATABASE_URL.
func WithDeps(fn func(*authkit.Deps)) Option {
	return func(s *setup) { s.deps = append(s.deps, fn) }
}

// New migrates AuthKit into a fresh schema, builds a Client on it, and returns
// the Client with the Outbox wired as its email and SMS senders. The defaults
// differ from a zero Config only where a test needs them to:
//
//   - Token: Issuer and Audience.
//   - Keys: an RSA key generated once per test binary.
//   - TwoFactor.TOTPSecretKey: random, so authenticator apps can enroll.
//   - HTTP: served (DirectPeerIP), without rate limits.
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
		Keys:      authkit.KeysConfig{Source: keys()},
		TwoFactor: authkit.TwoFactorConfig{TOTPSecretKey: key},
		HTTP:      authkit.HTTPConfig{DirectPeerIP: true, DisableRateLimiting: true},
	}
	deps := authkit.Deps{Email: outbox.Email(), SMS: outbox.SMS()}
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
	if err := authkit.Migrate(ctx, deps.Postgres, authkit.MigrateOptions{Schema: cfg.Schema, River: deps.River, RiverSchema: cfg.River.Schema}); err != nil {
		t.Fatalf("authtest: migrate: %v", err)
	}
	auth, err := authkit.New(ctx, cfg, deps)
	if err != nil {
		t.Fatalf("authtest: new client: %v", err)
	}
	t.Cleanup(auth.Close)
	return auth, outbox
}

var keys = sync.OnceValue(func() jwtkit.StaticKeySource {
	s, err := jwtkit.NewRSASigner(2048, "authtest")
	if err != nil {
		panic(err)
	}
	return jwtkit.StaticKeySource{Active: s, Pubs: map[string]crypto.PublicKey{s.KID(): s.PublicKey()}}
})

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
