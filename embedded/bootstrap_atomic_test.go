package embedded

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
)

func TestBootstrapFailureIsRetryable(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://audit.test"}}, Keyset{}, WithPostgres(pg.Pool))
	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{Username: "genesis", Email: "genesis@example.test", RootRole: "undefined-audit-role"}}}
	opts := BootstrapReconcileOptions{StartupOnly: true, Name: "audit"}
	_, firstErr := svc.ApplyBootstrapManifest(ctx, manifest, opts)
	if firstErr == nil {
		t.Fatal("invalid root role should fail")
	}
	var users, claims int
	if err := pg.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM profiles.users),(SELECT count(*) FROM profiles.bootstrap_applies)`).Scan(&users, &claims); err != nil {
		t.Fatal(err)
	}
	manifest.Users[0].RootRole = string(OwnerRoleName)
	_, retryErr := svc.ApplyBootstrapManifest(ctx, manifest, opts)
	if users != 0 || retryErr != nil {
		t.Fatalf("failed bootstrap stranded users=%d claims=%d firstErr=%v; corrected retryErr=%v", users, claims, firstErr, retryErr)
	}
}

func TestBootstrapDifferentNamesSerializeGlobally(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://audit.test"}}, Keyset{}, WithPostgres(pg.Pool))
	blocker, err := pg.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, `LOCK TABLE profiles.bootstrap_applies IN SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	type result struct {
		value BootstrapManifestResult
		err   error
	}
	results := make(chan result, 2)
	for _, name := range []string{"first", "second"} {
		go func(name string) {
			value, err := svc.ApplyBootstrapManifest(ctx, BootstrapManifest{Users: []BootstrapManifestUser{{Username: name, Email: name + "@example.test"}}}, BootstrapReconcileOptions{StartupOnly: true, Name: name})
			results <- result{value, err}
		}(name)
	}
	for {
		var blocked int
		if err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' `).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked == 2 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("did not observe both bootstrap calls waiting")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	a, b := <-results, <-results
	if a.err != nil || b.err != nil {
		t.Fatalf("unexpected bootstrap errors: %v %v", a.err, b.err)
	}
	var users int
	if err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM profiles.users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if !a.value.AlreadyApplied && !b.value.AlreadyApplied {
		t.Fatalf("two different names both applied genesis manifest: first=%+v second=%+v users=%d", a.value, b.value, users)
	}
}

func TestCanceledBootstrapDoesNotClaimCompletion(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://audit.test"}}, Keyset{}, WithPostgres(pg.Pool))
	if _, err := pg.Pool.Exec(ctx, `CREATE FUNCTION profiles.audit_delay_user() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$; CREATE TRIGGER audit_delay_user BEFORE INSERT ON profiles.users FOR EACH ROW EXECUTE FUNCTION profiles.audit_delay_user()`); err != nil {
		t.Fatal(err)
	}
	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{Username: "genesis", Email: "genesis@example.test", RootRole: string(OwnerRoleName)}}}
	opts := BootstrapReconcileOptions{StartupOnly: true, Name: "audit"}
	timeoutCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	_, firstErr := svc.ApplyBootstrapManifest(timeoutCtx, manifest, opts)
	if firstErr == nil {
		t.Fatal("delayed insert should be cancelled")
	}
	if _, err := pg.Pool.Exec(ctx, `DROP TRIGGER audit_delay_user ON profiles.users`); err != nil {
		t.Fatal(err)
	}
	retry, retryErr := svc.ApplyBootstrapManifest(ctx, manifest, opts)
	var users int
	if err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM profiles.users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if retryErr != nil || retry.AlreadyApplied || users != 1 {
		t.Fatalf("canceled bootstrap left completion claim: firstErr=%v retry=%+v retryErr=%v users=%d", firstErr, retry, retryErr, users)
	}
}
