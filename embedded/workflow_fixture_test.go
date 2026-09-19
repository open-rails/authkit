package embedded

// Shared fixtures for the retained public workflows and focused security checks.
import (
	"context"
	"fmt"

	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func bootstrapClaimNames(t *testing.T, ctx context.Context, pg *testdb.Postgres) []string {
	t.Helper()
	rows, err := pg.Pool.Query(ctx, `SELECT name FROM profiles.bootstrap_applies ORDER BY name`)
	if err != nil {
		t.Fatalf("read claims: %v", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("collect claims: %v", err)
	}
	return names
}

// hardeningEmailSender captures the verification code it is handed and every
// contact-changed / reset-link delivery.
type hardeningEmailSender struct {
	code           string
	resetLinks     int
	contactChanged []struct {
		to     string
		change ContactChange
	}
}

func (s *hardeningEmailSender) SendVerification(_ context.Context, _, _ string, msg VerificationMessage) error {
	s.code = msg.Code
	return nil
}

func (s *hardeningEmailSender) SendPasswordResetLink(context.Context, string, string, string) error {
	s.resetLinks++
	return nil
}

func (s *hardeningEmailSender) SendAccountRegistrationInvite(context.Context, string, string) error {
	return nil
}

func (s *hardeningEmailSender) SendLoginCode(context.Context, string, string, string) error {
	return nil
}

func (s *hardeningEmailSender) SendWelcome(context.Context, string, string) error { return nil }

func (s *hardeningEmailSender) SendDeviceKeyEnrolled(context.Context, string, string, DeviceKeyNotice) error {
	return nil
}

func (s *hardeningEmailSender) SendContactChanged(_ context.Context, to, _ string, change ContactChange) error {
	s.contactChanged = append(s.contactChanged, struct {
		to     string
		change ContactChange
	}{to, change})
	return nil
}

func newHardeningService(t *testing.T) (*Client, *hardeningEmailSender) {
	t.Helper()
	sender := &hardeningEmailSender{}
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://hardening.test"}}, Keyset{},
		WithPostgres(testdb.Pool(t)), WithEphemeralStore(memorystore.NewKV()), WithEmailSender(sender))
	return svc, sender
}

func newHardeningUser(t *testing.T, ctx context.Context, svc *Client, tag string) (*User, string) {
	t.Helper()
	username := fmt.Sprintf("hard-%s-%d", tag, time.Now().UnixNano())
	email := username + "@example.test"
	u, err := svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = svc.pg.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })
	return u, email
}

// Test-only Deps builders: the engine takes one Deps value; tests compose it
// from these so a call site names only what it wires.
type Option func(*Deps)

func WithPostgres(pool *pgxpool.Pool) Option { return func(d *Deps) { d.Postgres = pool } }

func WithEphemeralStore(store EphemeralStore) Option {
	return func(d *Deps) { d.EphemeralStore = store }
}

func WithEmailSender(s EmailSender) Option { return func(d *Deps) { d.Email = s } }

func depsOf(opts ...Option) Deps {
	var d Deps
	for _, o := range opts {
		if o != nil {
			o(&d)
		}
	}
	return d
}

func insertBareUser(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE id=$1::uuid`, id)
	})
	return id
}

// mustNewService is NewService for tests: a config the constructor rejects fails the test.
func mustNewWithKeys(t testing.TB, cfg Config, keys Keyset, opts ...Option) *Client {
	t.Helper()
	svc, err := NewWithKeys(cfg, keys, depsOf(opts...))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
