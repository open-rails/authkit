package critical_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// cutoffBarrier pauses the real deletion scan at the PostgreSQL driver boundary.
// It changes no query or result. The test can then age only its owned timestamp
// fixtures relative to the exact cutoff the worker actually obtained from PG.
// A wall-clock sample before starting the worker cannot exercise equality.
type cutoffBarrier struct {
	arrived chan time.Time
	release chan struct{}
	claimed atomic.Bool
}

func (b *cutoffBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !strings.HasPrefix(data.SQL, "-- name: AccountDeletionsDue :many") || !b.claimed.CompareAndSwap(false, true) {
		return ctx
	}
	select {
	case b.arrived <- data.Args[0].(time.Time):
	case <-ctx.Done():
		return ctx
	}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return ctx
}

func (*cutoffBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

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
		checkNativeCallbackTenants(t)
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
	t.Run("AK-J25-C03_due_boundary_and_startup_catchup_respect_scan_cutoff", func(t *testing.T) {
		var mu sync.Mutex
		seen := map[string]iam.UserDeletion{}
		barrier := &cutoffBarrier{arrived: make(chan time.Time, 1), release: make(chan struct{})}
		var release sync.Once
		t.Cleanup(func() { release.Do(func() { close(barrier.release) }) })
		f := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) {
			cfg := d.Postgres.Config()
			cfg.ConnConfig.Tracer = barrier
			pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
			noError(t, err)
			t.Cleanup(pool.Close)
			d.Postgres = pool
			d.OnPurge = func(_ context.Context, deletion iam.UserDeletion) error {
				mu.Lock()
				seen[deletion.UserID] = deletion
				mu.Unlock()
				return nil
			}
		}))
		created := time.Now().UTC().Add(-60 * 24 * time.Hour)
		deleted := created.Add(29 * 24 * time.Hour)
		imported, err := f.auth.ImportUsers(t.Context(), []iam.ImportUser{{Username: "beforedue", CreatedAt: &created, DeletedAt: &deleted}, {Username: "atdue", CreatedAt: &created, DeletedAt: &deleted}, {Username: "pastdue", CreatedAt: &created, DeletedAt: &deleted}}, iam.ImportOptions{})
		noError(t, err)
		if imported.Inserted != 3 {
			t.Fatalf("due fixture rejected: %+v", imported)
		}
		f.startFleet(t)
		var anchor time.Time
		select {
		case anchor = <-barrier.arrived:
		case <-time.After(10 * time.Second):
			t.Fatal("real deletion sweep did not reach its database cutoff")
		}
		// Only these imported fixture timestamps are adjusted. Lifecycle state,
		// recipients, receipts and all purge effects still come from AuthKit.
		tx, err := f.pool.Begin(t.Context())
		noError(t, err)
		defer tx.Rollback(context.Background())
		for i, offset := range []time.Duration{time.Microsecond, 0, -time.Microsecond} {
			purgeAt := anchor.Add(offset)
			deletedAt := purgeAt.Add(-30 * 24 * time.Hour)
			_, err = tx.Exec(t.Context(), "UPDATE "+pgx.Identifier{f.schema, "users"}.Sanitize()+" SET deleted_at=$2 WHERE id=$1", imported.Rows[i].UserID, deletedAt)
			noError(t, err)
			_, err = tx.Exec(t.Context(), "UPDATE "+pgx.Identifier{f.schema, "account_deletions"}.Sanitize()+" SET deleted_at=$2, purge_at=$3 WHERE user_id=$1", imported.Rows[i].UserID, deletedAt, purgeAt)
			noError(t, err)
		}
		noError(t, tx.Commit(t.Context()))
		release.Do(func() { close(barrier.release) })
		f.purged(t, imported.Rows[1].UserID)
		f.purged(t, imported.Rows[2].UserID)
		still, err := f.auth.User(t.Context(), iam.UserByID(imported.Rows[0].UserID), authkit.IncludeDeleted())
		noError(t, err)
		if still.DeletedAt == nil {
			t.Fatal("account beyond the fixed scan cutoff was purged")
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

// One AuthKit runtime serves two explicitly selected account directories. The
// application's policy callback observes the resolved target, not a user-ID
// guess or the default tenant of its construction.
func checkNativeCallbackTenants(t *testing.T) {
	t.Helper()
	if tenant, ok := authkit.TenantFromContext(context.Background()); ok || !tenant.IsZero() {
		t.Fatal("unscoped context invented a target")
	}
	type observed struct {
		tenant       iam.TenantID
		present      bool
		user, client string
	}
	deletion, consent := make(chan observed, 4), make(chan observed, 4)
	var selected atomic.Pointer[http.Handler]
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := selected.Load(); h != nil {
			(*h).ServeHTTP(w, r)
			return
		}
		http.Error(w, "starting", http.StatusServiceUnavailable)
	}))
	t.Cleanup(front.Close)
	var persona iam.Persona
	f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Token.Issuer = front.URL
		persona = c.Roles.Persona("callbackshop", authkit.OAuthClients).Persona
	}), authtest.WithDeps(func(d *authkit.Deps) {
		d.DeletionCheck = func(ctx context.Context, user string) error {
			tenant, ok := authkit.TenantFromContext(ctx)
			deletion <- observed{tenant: tenant, present: ok, user: user}
			return iam.RefuseDeletion("callback policy")
		}
		d.ConsentRevocationCheck = func(ctx context.Context, user, client string) error {
			tenant, ok := authkit.TenantFromContext(ctx)
			consent <- observed{tenant: tenant, present: ok, user: user, client: client}
			return iam.RefuseConsentRevocation("callback policy")
		}
	}))
	f.startFleet(t)
	other := iam.NewTenantID()
	noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: other, Slug: "lifecycle-other"}))
	var firstToken string
	for _, tenant := range []iam.TenantID{f.tenant, other} {
		view, err := f.auth.ForTenant(t.Context(), tenant)
		noError(t, err)
		handler := view.Handler()
		selected.Store(&handler)
		caller := &fixture{auth: view, server: front}
		user := authtest.NewUser(t, view)
		session := caller.signIn(t, user)
		if firstToken == "" {
			firstToken = session.AccessToken
		} else {
			caller.call(t, "DELETE", "/me", firstToken, nil).want(t, http.StatusForbidden, "forbidden")
			select {
			case <-deletion:
				t.Fatal("foreign token reached callback")
			default:
			}
		}
		owner := iam.UserSubject(user.ID)
		group, err := view.CreateGroup(t.Context(), iam.NewGroup{Persona: persona, Owner: &owner})
		noError(t, err)
		client, err := view.CreateGroupOAuthClient(t.Context(), iam.SystemIdentity(), iam.GroupByID(group.ID), iam.NewOAuthClient{ClientName: "Callback", RedirectURIs: []string{"https://client.example/callback"}, TokenEndpointAuthMethod: iam.OAuthClientSecretBasic, Scope: "openid"})
		noError(t, err)
		as := authtest.Attach(t, view, front)
		as.AuthorizeAs(t, session, authtest.CodeFlow{ClientID: client.ClientID, ClientSecret: *client.ClientSecret, RedirectURI: "https://client.example/callback", Scopes: []string{"openid"}, Consent: true})
		caller.call(t, "DELETE", "/me/oauth-consents/"+client.ClientID, session.AccessToken, nil).want(t, http.StatusConflict, "consent_revocation_refused")
		var got observed
		select {
		case got = <-consent:
		default:
			t.Fatal("consent HTTP refusal did not invoke the host callback")
		}
		if !got.present || got.tenant != tenant || got.user != user.ID || got.client != client.ClientID {
			t.Fatalf("consent callback target: %+v, want tenant%s user%s", got, tenant, user.ID)
		}
		caller.call(t, "DELETE", "/me", session.AccessToken, nil).want(t, http.StatusConflict, "deletion_refused")
		select {
		case got = <-deletion:
		default:
			t.Fatal("deletion HTTP refusal did not invoke the host callback")
		}
		if !got.present || got.tenant != tenant || got.user != user.ID {
			t.Fatalf("deletion callback target: %+v, want tenant%s user%s", got, tenant, user.ID)
		}
		retained, err := view.User(t.Context(), iam.UserByID(user.ID))
		noError(t, err)
		if retained.DeletedAt != nil {
			t.Fatal("refused deletion changed the account")
		}
		kept, err := view.OAuthConsents(t.Context(), user.ID)
		noError(t, err)
		if len(kept) != 1 || kept[0].ClientID != client.ClientID {
			t.Fatal("refused revocation changed consent")
		}
	}
}
