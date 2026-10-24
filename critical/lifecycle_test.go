package critical_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	riverkit "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

func (f *fixture) startFleet(t *testing.T) *river.Client[pgx.Tx] {
	t.Helper()
	fleet, err := riverkit.New(t.Context(), f.deps.Postgres, &river.Config{Schema: f.schema}, f.auth.RiverJobs())
	noError(t, err)
	noError(t, fleet.Start(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		noError(t, fleet.Stop(ctx))
	})
	noError(t, f.auth.Start(context.Background(), authkit.WithRiverClient(fleet)))
	return fleet
}
func (f *fixture) retrySweep(t *testing.T, fleet *river.Client[pgx.Tx], kind, issuer string) {
	t.Helper()
	var selected *rivertype.JobRow
	eventually(t, "completed owned sweep", func() bool {
		page, err := fleet.JobList(t.Context(), river.NewJobListParams().Kinds(kind).First(100))
		noError(t, err)
		for _, job := range page.Jobs {
			var args struct {
				Schema string `json:"schema"`
				Issuer string `json:"issuer"`
			}
			decode(t, job.EncodedArgs, &args)
			if args.Schema == f.schema && args.Issuer == issuer {
				if job.State == rivertype.JobStateAvailable || job.State == rivertype.JobStatePending || job.State == rivertype.JobStateRunning || job.State == rivertype.JobStateRetryable || job.State == rivertype.JobStateScheduled {
					return false
				}
				if job.State == rivertype.JobStateCompleted && (selected == nil || job.ID > selected.ID) {
					selected = job
				}
			}
		}
		return selected != nil
	})
	previous := selected.Attempt
	_, err := fleet.JobRetry(t.Context(), selected.ID)
	noError(t, err)
	eventually(t, "owned sweep retry completed", func() bool {
		job, err := fleet.JobGet(t.Context(), selected.ID)
		noError(t, err)
		if job.State == rivertype.JobStateDiscarded || job.State == rivertype.JobStateCancelled {
			t.Fatalf("sweep did not execute: %s %v", job.State, job.Errors)
		}
		return job.State == rivertype.JobStateCompleted && job.Attempt > previous
	})
}
func goodBatch(t *testing.T, rows []iam.OpResult, err error) {
	t.Helper()
	noError(t, err)
	for _, row := range rows {
		if row.Err != nil {
			t.Fatalf("public batch item%s failed: %v", row.ID, row.Err)
		}
	}
}
func (f *fixture) purged(t *testing.T, id string) {
	t.Helper()
	eventually(t, "account purge visible through public lookup", func() bool {
		_, err := f.auth.User(t.Context(), iam.UserByID(id), authkit.IncludeDeleted())
		if errors.Is(err, iam.ErrUserNotFound) {
			return true
		}
		noError(t, err)
		return false
	})
}

func TestCriticalAccountLifecycle(t *testing.T) {
	t.Run("AK-J25-C01_ban_authority_and_last_owner_survive_adversarial_calls", func(t *testing.T) {
		f := newFixture(t)
		group, owner, who := f.ownedGroup(t)
		if err := f.auth.Ban(t.Context(), who, owner.ID, iam.Ban{}); !errors.Is(err, iam.ErrCannotTargetSelf) {
			t.Fatalf("self ban was accepted: %v", err)
		}
		if err := f.auth.Ban(t.Context(), iam.SystemIdentity(), owner.ID, iam.Ban{}); !errors.Is(err, iam.ErrLastOwner) {
			t.Fatalf("last owner was disabled: %v", err)
		}
		u := f.user(t)
		token := f.signIn(t, u)
		intruder := f.identity(t, token.AccessToken)
		if err := f.auth.Ban(t.Context(), intruder, owner.ID, iam.Ban{}); !errors.Is(err, iam.ErrInsufficientAuthority) {
			t.Fatalf("unprivileged peer ban: %v", err)
		}
		noError(t, f.auth.Ban(t.Context(), iam.SystemIdentity(), u.ID, iam.Ban{}))
		noError(t, f.auth.Unban(t.Context(), iam.SystemIdentity(), u.ID))
		f.signIn(t, u)
		cl, err := f.auth.Verify(t.Context(), token.AccessToken)
		noError(t, err)
		if !errors.Is(f.auth.CheckSession(t.Context(), cl), iam.ErrSessionRevoked) {
			t.Fatal("unban revived a retired session")
		}
		roles, err := f.auth.GroupRoles(t.Context(), iam.GroupByID(group.ID), []iam.Subject{iam.UserSubject(owner.ID)})
		noError(t, err)
		if roles[iam.UserSubject(owner.ID)] != f.shop.Owner {
			t.Fatal("refused calls changed owner authority")
		}
	})
	t.Run("AK-J25-C02_soft_delete_tombstones_and_authorized_restore", func(t *testing.T) {
		f := newFixture(t)
		f.startFleet(t)
		u := f.user(t)
		token := f.signIn(t, u)
		rows, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		goodBatch(t, rows, err)
		_, err = f.auth.User(t.Context(), iam.UserByID(u.ID))
		if !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatal("deleted account remained in ordinary reads")
		}
		deleted, err := f.auth.User(t.Context(), iam.UserByID(u.ID), authkit.IncludeDeleted())
		noError(t, err)
		if deleted.DeletedAt == nil {
			t.Fatal("deleted account lost its recovery record")
		}
		public, err := f.auth.PublicUsers(t.Context(), []string{u.ID})
		noError(t, err)
		tombstone := public[u.ID]
		if tombstone.ID != u.ID || !tombstone.Deleted || tombstone.Username != "" || tombstone.CreatedAt != nil || len(tombstone.PublicMetadata) != 0 {
			t.Fatal("deleted account leaked its old public profile")
		}
		rows, err = f.auth.RestoreUsers(t.Context(), auth.Identity{}, []string{u.ID})
		noError(t, err)
		if len(rows) != 1 || rows[0].Err == nil {
			t.Fatal("unverified identity restored an account")
		}
		rows, err = f.auth.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		goodBatch(t, rows, err)
		restored, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if restored.DeletedAt != nil {
			t.Fatal("authorized restoration did not reopen the account")
		}
		cl, err := f.auth.Verify(t.Context(), token.AccessToken)
		noError(t, err)
		if !errors.Is(f.auth.CheckSession(t.Context(), cl), iam.ErrSessionRevoked) {
			t.Fatal("restore revived old credentials")
		}
	})
	t.Run("AK-J25-C03_due_boundary_and_startup_catchup_preserve_recoverable_accounts", func(t *testing.T) {
		var mu sync.Mutex
		seen := map[string]iam.UserDeletion{}
		f := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) {
			d.OnPurge = func(_ context.Context, deletion iam.UserDeletion) error {
				mu.Lock()
				seen[deletion.UserID] = deletion
				mu.Unlock()
				return nil
			}
		}))
		anchor := time.Now().UTC().Truncate(time.Microsecond)
		created := anchor.Add(-60 * 24 * time.Hour)
		future := anchor.Add(-30*24*time.Hour + time.Hour)
		due := anchor.Add(-30 * 24 * time.Hour)
		past := due.Add(-time.Hour)
		imported, err := f.auth.ImportUsers(t.Context(), []iam.ImportUser{{Username: "beforedue", CreatedAt: &created, DeletedAt: &future}, {Username: "atdue", CreatedAt: &created, DeletedAt: &due}, {Username: "pastdue", CreatedAt: &created, DeletedAt: &past}}, iam.ImportOptions{})
		noError(t, err)
		if imported.Inserted != 3 {
			t.Fatalf("due fixture rejected: %+v", imported)
		}
		f.startFleet(t)
		f.purged(t, imported.Rows[1].UserID)
		f.purged(t, imported.Rows[2].UserID)
		still, err := f.auth.User(t.Context(), iam.UserByID(imported.Rows[0].UserID), authkit.IncludeDeleted())
		noError(t, err)
		if still.DeletedAt == nil {
			t.Fatal("recoverable account changed before its deadline")
		}
		mu.Lock()
		defer mu.Unlock()
		if len(seen) != 2 {
			t.Fatalf("cleanup targeted%d accounts", len(seen))
		}
		for _, record := range seen {
			if record.PurgeAt.Sub(record.DeletedAt) != 30*24*time.Hour || record.TenantID != f.tenant {
				t.Fatal("cleanup obligation lost its fixed window or tenant")
			}
		}
		if !seen[imported.Rows[1].UserID].PurgeAt.Equal(anchor) {
			t.Fatal("at-boundary import changed its declared purge deadline")
		}
	})
	t.Run("AK-J25-C04_finalization_fences_a_concurrent_restore", func(t *testing.T) {
		entered := make(chan struct{}, 1)
		release := make(chan struct{})
		var once sync.Once
		t.Cleanup(func() { once.Do(func() { close(release) }) })
		f := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) {
			d.OnPurge = func(ctx context.Context, _ iam.UserDeletion) error {
				select {
				case entered <- struct{}{}:
				default:
				}
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}))
		f.startFleet(t)
		u := f.user(t)
		rows, err := f.auth.PurgeUsers(t.Context(), []string{u.ID})
		goodBatch(t, rows, err)
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("real cleanup worker did not reach its external obligation")
		}
		rows, err = f.auth.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		noError(t, err)
		if len(rows) != 1 || rows[0].Err == nil {
			t.Fatal("restore crossed an irreversible finalization")
		}
		if e, ok := iam.AsError(rows[0].Err); !ok || e.Code() != "account_recovery_expired" {
			t.Fatalf("restore failure=%v", rows[0].Err)
		}
		once.Do(func() { close(release) })
		f.purged(t, u.ID)
	})
	t.Run("AK-J25-C05_failed_callback_retries_without_holding_the_one_slot_pool", func(t *testing.T) {
		var client *authkit.Client
		var attempts atomic.Int32
		f := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) {
			cfg := d.Postgres.Config()
			cfg.MaxConns = 1
			pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
			noError(t, err)
			t.Cleanup(pool.Close)
			d.Postgres = pool
			d.OnPurge = func(ctx context.Context, deletion iam.UserDeletion) error {
				user, err := client.User(ctx, iam.UserByID(deletion.UserID), authkit.IncludeDeleted())
				if err != nil {
					return err
				}
				if user.ID != deletion.UserID {
					return errors.New("callback read wrong account")
				}
				if attempts.Add(1) == 1 {
					return errors.New("external cleanup temporarily unavailable")
				}
				return nil
			}
		}))
		client = f.auth
		fleet := f.startFleet(t)
		u := f.user(t)
		rows, err := f.auth.PurgeUsers(t.Context(), []string{u.ID})
		goodBatch(t, rows, err)
		eventually(t, "first failed external cleanup", func() bool { return attempts.Load() >= 1 })
		_, err = f.auth.User(t.Context(), iam.UserByID(u.ID), authkit.IncludeDeleted())
		noError(t, err)
		f.retrySweep(t, fleet, "authkit_account_delete_due", authtest.Issuer)
		f.purged(t, u.ID)
		if attempts.Load() != 2 {
			t.Fatalf("unexpected callback attempts%d", attempts.Load())
		}
	})
	t.Run("AK-J25-C06_duplicate_and_late_sweeps_do_not_resurrect_or_repeat_effects", func(t *testing.T) {
		var calls atomic.Int32
		f := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) {
			d.OnPurge = func(context.Context, iam.UserDeletion) error { calls.Add(1); return nil }
		}))
		fleet := f.startFleet(t)
		u := f.user(t)
		rows, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		goodBatch(t, rows, err)
		rows, err = f.auth.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		goodBatch(t, rows, err)
		f.retrySweep(t, fleet, "authkit_account_delete_due", authtest.Issuer)
		_, err = f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if calls.Load() != 0 {
			t.Fatal("late sweep erased a restored account")
		}
		rows, err = f.auth.PurgeUsers(t.Context(), []string{u.ID})
		goodBatch(t, rows, err)
		f.purged(t, u.ID)
		f.retrySweep(t, fleet, "authkit_account_delete_due", authtest.Issuer)
		if calls.Load() != 1 {
			t.Fatalf("completed cleanup repeated%d times", calls.Load())
		}
		page, err := f.auth.ListEvents(t.Context(), iam.EventQuery{Types: []string{"user.purged"}})
		noError(t, err)
		if len(page.Events) != 1 || page.Events[0].UserID != u.ID {
			t.Fatal("purge replay duplicated or lost the retained fact")
		}
	})
	t.Run("AK-J25-C07_account_retirement_ends_user_credentials_but_not_group_automation", func(t *testing.T) {
		f := newFixture(t)
		f.startFleet(t)
		g, u, who := f.ownedGroup(t)
		replacement := f.user(t)
		f.grant(t, g, replacement, f.shop.Owner)
		session := f.signIn(t, u)
		pat, err := f.auth.CreatePersonalAccessToken(t.Context(), who, iam.NewPersonalAccessToken{Name: "owner token", GroupID: g.ID, Permissions: []iam.Perm{f.read}})
		noError(t, err)
		key, err := f.auth.CreateAPIKey(t.Context(), who, iam.GroupByID(g.ID), iam.NewAPIKey{Name: "group automation", Role: f.reader})
		noError(t, err)
		proof := f.passwordlessProof(t, u.Email, "code")
		rows, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
		goodBatch(t, rows, err)
		_, err = f.authenticate(t, session.AccessToken)
		if !errors.Is(err, auth.ErrRevoked) {
			t.Fatalf("deleted session retained authority: %v", err)
		}
		_, err = f.auth.ResolvePersonalAccessToken(t.Context(), pat.Secret)
		if !errors.Is(err, iam.ErrPersonalAccessTokenInvalid) {
			t.Fatalf("deleted owner's PAT retained authority: %v", err)
		}
		f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"identifier": u.Email, "code": proof.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		_, err = f.authenticate(t, key.Secret)
		noError(t, err)
	})
}
