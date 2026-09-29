package engine

// Shared fixtures for the retained public workflows and focused security checks.
import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testoutbox"
	"github.com/stretchr/testify/require"
)

func bootstrapClaimNames(t *testing.T, ctx context.Context, pg *testdb.Postgres) []string {
	t.Helper()
	rows, err := pg.Pool.Query(ctx, `SELECT name FROM bootstrap_applies ORDER BY name`)
	if err != nil {
		t.Fatalf("read claims: %v", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("collect claims: %v", err)
	}
	return names
}

func newHardeningService(t *testing.T) (*Engine, *testoutbox.Outbox) {
	t.Helper()
	sender := &testoutbox.Outbox{}
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://hardening.test"}}, keyset{},
		Deps{Postgres: testdb.Pool(t), Email: sender.Email()})
	return svc, sender
}

func newHardeningUser(t *testing.T, ctx context.Context, svc *Engine, tag string) (*userRecord, string) {
	t.Helper()
	username := fmt.Sprintf("hard-%s-%d", tag, time.Now().UnixNano())
	email := username + "@example.test"
	u, err := svc.createUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = svc.pg.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, u.ID) })
	require.NoError(t, svc.markEmailVerified(ctx, u.ID))
	u.EmailVerified = true
	return u, email
}

func insertBareUser(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `INSERT INTO users DEFAULT VALUES RETURNING id::text`).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1::uuid`, id)
	})
	return id
}

// mustNewWithKeys constructs a client and releases its owned resources after the test.
func mustNewWithKeys(t testing.TB, cfg Config, keys keyset, deps Deps) *Engine {
	t.Helper()
	svc, err := newEngineWithKeys(cfg, keys, deps)
	if err != nil {
		t.Fatalf("NewWithKeys: %v", err)
	}
	t.Cleanup(svc.Close)
	return svc
}
