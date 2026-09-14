package embedded

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	migrations "github.com/open-rails/authkit/migrations/postgres"
	"github.com/open-rails/migratekit"
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

// #259: migration 0011 backfills one claim on a database whose graph predates
// StartupOnly claims, so every bootstrap name boots afterwards; a graph-less
// database gets no row (the fresh-database assertion above).
func TestBootstrapClaimBackfillMigrationUnlocksPreClaimDatabase(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	if _, err := pg.Pool.Exec(ctx, `DROP SCHEMA profiles CASCADE`); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := pg.Pool.Exec(ctx, `DELETE FROM public.migrations WHERE app = 'authkit'`); err != nil {
		t.Fatalf("reset tracking: %v", err)
	}
	ms, err := migratekit.LoadFromFS(migrations.FS)
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	backfill := -1
	for i, migration := range ms {
		if migration.Name == "0011_bootstrap_claim_backfill.up.sql" {
			backfill = i
			break
		}
	}
	if backfill < 0 {
		t.Fatal("bootstrap backfill migration not found")
	}
	sqlDB, err := sql.Open("pgx", pg.URL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	runner := migratekit.NewPostgres(sqlDB, "authkit")
	if err := runner.ApplyMigrations(ctx, ms[:backfill]); err != nil {
		t.Fatalf("apply pre-backfill migrations: %v", err)
	}
	if _, err := pg.Pool.Exec(ctx, `INSERT INTO profiles.users (email, username, email_verified) VALUES ('legacy@example.com', 'legacy', true)`); err != nil {
		t.Fatalf("seed legacy graph: %v", err)
	}
	if err := runner.ApplyMigrations(ctx, ms); err != nil {
		t.Fatalf("apply backfill migration: %v", err)
	}
	if names := bootstrapClaimNames(t, ctx, pg); len(names) != 1 || names[0] != "authkit.backfill" {
		t.Fatalf("claims after backfill=%v", names)
	}

	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pg.Pool))
	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{
		Username: "legacy", Email: "legacy@example.com", EmailVerified: true,
		Password: &BootstrapUserPassword{Plaintext: "bootstrap-password-1"}, RootRole: string(OwnerRoleName),
	}}}
	for _, name := range []string{"default", "openrails"} {
		res, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{StartupOnly: true, Name: name})
		if err != nil || !res.AlreadyApplied || res.PasswordsSet != 0 || res.RootRoleAssignments != 0 {
			t.Fatalf("name %q res=%+v err=%v, want already applied", name, res, err)
		}
	}
}
