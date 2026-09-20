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
	store := memorystore.NewKV()
	t.Cleanup(store.Close)
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://hardening.test"}}, Keyset{},
		Deps{Postgres: testdb.Pool(t), EphemeralStore: store, Email: sender})
	return svc, sender
}

func newHardeningUser(t *testing.T, ctx context.Context, svc *Client, tag string) (*User, string) {
	t.Helper()
	username := fmt.Sprintf("hard-%s-%d", tag, time.Now().UnixNano())
	email := username + "@example.test"
	u, err := svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = svc.pg.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, u.ID) })
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
func mustNewWithKeys(t testing.TB, cfg Config, keys Keyset, deps Deps) *Client {
	t.Helper()
	svc, err := NewWithKeys(cfg, keys, deps)
	if err != nil {
		t.Fatalf("NewWithKeys: %v", err)
	}
	t.Cleanup(svc.Close)
	return svc
}
