package embedded

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/authkitmigrate"
	"github.com/open-rails/authkit/internal/testdb"
)

func TestBootstrapRollsBackEverySeedStage(t *testing.T) {
	for _, table := range []string{"remote_applications", "users", "user_passwords", "group_user_roles"} {
		t.Run(table, func(t *testing.T) {
			pg := testdb.ScratchPostgres(t)
			ctx := context.Background()
			svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://bootstrap.test"}}, Keyset{}, WithPostgres(pg.Pool))
			state := func() [6]int {
				t.Helper()
				var n [6]int
				err := pg.Pool.QueryRow(ctx, `SELECT
					(SELECT count(*) FROM profiles.bootstrap_applies),
					(SELECT count(*) FROM profiles.permission_groups),
					(SELECT count(*) FROM profiles.remote_applications),
					(SELECT count(*) FROM profiles.users),
					(SELECT count(*) FROM profiles.user_passwords),
					(SELECT count(*) FROM profiles.group_user_roles)`).
					Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5])
				if err != nil {
					t.Fatal(err)
				}
				return n
			}
			before := state()
			_, err := pg.Pool.Exec(ctx, fmt.Sprintf(`
				CREATE FUNCTION profiles.fail_seed() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'injected seed failure'; END $$;
				CREATE TRIGGER fail_seed BEFORE INSERT ON profiles.%s
				FOR EACH ROW EXECUTE FUNCTION profiles.fail_seed()`, table))
			if err != nil {
				t.Fatal(err)
			}
			enabled := true
			manifest := BootstrapManifest{
				RemoteApplications: []BootstrapManifestRemoteApplication{{Slug: "seed-app", Issuer: "https://seed-app.test", JWKSURI: "https://seed-app.test/keys", Enabled: &enabled}},
				Users:              []BootstrapManifestUser{{Username: "seed-owner", Email: "owner@seed.test", RootRole: string(OwnerRoleName), Password: &BootstrapUserPassword{Plaintext: "Seed-password-123"}}},
			}
			opts := BootstrapReconcileOptions{StartupOnly: true}
			res, err := svc.ApplyBootstrapManifest(ctx, manifest, opts)
			if err == nil || res != (BootstrapManifestResult{}) {
				t.Fatalf("failed transaction returned a success receipt: result=%+v err=%v", res, err)
			}
			if after := state(); after != before {
				t.Fatalf("seed failure left partial state: before=%v after=%v", before, after)
			}
			if _, err := pg.Pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER fail_seed ON profiles.%s`, table)); err != nil {
				t.Fatal(err)
			}
			res, err = svc.ApplyBootstrapManifest(ctx, manifest, opts)
			if err != nil || res.AlreadyApplied || res.UsersCreated != 1 || res.RemoteApplications != 1 {
				t.Fatalf("corrected retry failed: result=%+v err=%v", res, err)
			}
		})
	}
}

func TestBootstrapUsesOnePoolConnection(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := pg.Pool.Config()
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://bootstrap.test"}}, Keyset{}, WithPostgres(pool))
	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{Username: "seed-owner", Email: "owner@seed.test", RootRole: string(OwnerRoleName), Password: &BootstrapUserPassword{Plaintext: "Seed-password-123"}}}}
	for _, startup := range []bool{true, false} {
		if _, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{StartupOnly: startup}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBootstrapSchemasAreIndependent(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := authkitmigrate.New(pg.Pool, &authkitmigrate.Config{Schema: "other"}).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	newClient := func(schema string) *Client {
		return mustNewWithKeys(t, Config{Schema: schema, Token: TokenConfig{Issuer: "https://bootstrap.test"}}, Keyset{}, WithPostgres(pg.Pool))
	}
	first, second := newClient("profiles"), newClient("other")
	blocker, err := pg.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(ctx)
	if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('authkit.bootstrap.profiles', 0))`); err != nil {
		t.Fatal(err)
	}
	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{Username: "seed-owner", Email: "owner@seed.test"}}}
	firstDone := make(chan error, 1)
	go func() {
		_, err := first.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{StartupOnly: true})
		firstDone <- err
	}()
	if res, err := second.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{StartupOnly: true}); err != nil || res.UsersCreated != 1 {
		t.Fatalf("unrelated schema was blocked: result=%+v err=%v", res, err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	var counts [2]int
	if err := pg.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM profiles.users), (SELECT count(*) FROM other.users)`).Scan(&counts[0], &counts[1]); err != nil {
		t.Fatal(err)
	}
	if counts != [2]int{1, 1} {
		t.Fatalf("wrong independent seed counts: %v", counts)
	}
}
