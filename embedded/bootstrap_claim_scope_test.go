package embedded

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
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

func rootRolesOf(t *testing.T, ctx context.Context, svc *Client, userID string) []string {
	t.Helper()
	members, err := svc.ListGroupMembers(ctx, authkit.RootGroup())
	if err != nil && !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("list root members: %v", err)
	}
	var roles []string
	for _, m := range members {
		if m.SubjectID == userID {
			roles = append(roles, string(m.Role))
		}
	}
	return roles
}

// #259: a non-empty authority graph with an EMPTY claim table was seeded by
// something that left no record; that is the only case still refused, and the
// refusal leaves no claim behind.
func TestBootstrapClaimGraphWithoutAnyClaimRefuses(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pg.Pool))

	if _, err := svc.CreateUser(ctx, "existing@example.com", "existing"); err != nil {
		t.Fatalf("seed unrecorded user: %v", err)
	}
	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{
		Username: "existing", Email: "existing@example.com", EmailVerified: true,
		Password: &BootstrapUserPassword{Plaintext: "bootstrap-password-1"}, RootRole: string(OwnerRoleName),
	}}}
	for _, name := range []string{"default", "openrails"} {
		_, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{StartupOnly: true, Name: name})
		if !errors.Is(err, ErrBootstrapDatabaseNotEmpty) {
			t.Fatalf("name %q err=%v, want ErrBootstrapDatabaseNotEmpty", name, err)
		}
	}
	if names := bootstrapClaimNames(t, ctx, pg); len(names) != 0 {
		t.Fatalf("refusal must leave no claim, got %v", names)
	}
	user, err := svc.getUserByUsername(ctx, "existing")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if err := svc.CheckUserPassword(ctx, user.ID, "bootstrap-password-1"); err == nil {
		t.Fatal("refused apply must not set a password")
	}
	if roles := rootRolesOf(t, ctx, svc, user.ID); len(roles) != 0 {
		t.Fatalf("refused apply must not assert root roles, got %v", roles)
	}
}
