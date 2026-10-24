package critical_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testclock"
)

func (f *fixture) ageTerminal(t *testing.T, table, id string) {
	t.Helper()
	if table != "api_keys" && table != "group_invite_links" {
		t.Fatal("unsupported fixture retention clock")
	}
	tag, err := f.pool.Exec(t.Context(), "UPDATE "+pgx.Identifier{f.schema, table}.Sanitize()+" SET revoked_at=statement_timestamp()-interval '91 days' WHERE id=$1 AND revoked_at IS NOT NULL", id)
	noError(t, err)
	if tag.RowsAffected() != 1 {
		t.Fatal("retention clock did not identify its already-revoked fixture")
	}
}

func TestCriticalMaintenance(t *testing.T) {
	t.Run("AK-J32-C01_expired_authority_is_refused_before_cleanup_runs", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		session := f.signIn(t, u)
		claims, err := f.auth.Verify(t.Context(), session.AccessToken)
		noError(t, err)
		_, err = f.pool.Exec(t.Context(), "UPDATE "+pgx.Identifier{f.schema, "refresh_sessions"}.Sanitize()+" SET expires_at=statement_timestamp()-interval '1 second' WHERE id=$1", claims.SessionID)
		noError(t, err)
		if !errors.Is(f.auth.CheckSession(t.Context(), claims), iam.ErrSessionRevoked) {
			t.Fatal("expired session remained usable before maintenance")
		}
		f.call(t, "POST", "/token", "", map[string]string{"grant_type": "refresh_token", "refresh_token": *session.RefreshToken}).want(t, http.StatusUnauthorized, "invalid_token")
		proof := f.passwordlessProof(t, u.Email, "code")
		f.expireProofs(t)
		f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"identifier": u.Email, "code": proof.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		key, _, _ := f.key(t)
		_, err = f.pool.Exec(t.Context(), "UPDATE "+pgx.Identifier{f.schema, "api_keys"}.Sanitize()+" SET expires_at=statement_timestamp()-interval '1 second' WHERE id=$1", key.APIKey.ID)
		noError(t, err)
		_, err = f.auth.ResolveAPIKey(t.Context(), key.Secret)
		if !errors.Is(err, iam.ErrAPIKeyExpired) {
			t.Fatalf("expired key waited for GC to lose authority: %v", err)
		}
	})
	t.Run("AK-J32-C02_terminal_keys_and_invites_keep_only_their_retention_window", func(t *testing.T) {
		f := newFixture(t)
		fleet := f.startFleet(t)
		f.retrySweep(t, fleet, "authkit_cleanup_expired_auth_state", "")
		old, group, who := f.key(t)
		ref := iam.GroupByID(group.ID)
		newer, err := f.auth.CreateAPIKey(t.Context(), who, ref, iam.NewAPIKey{Name: "recently revoked", Role: f.reader})
		noError(t, err)
		for _, id := range []string{old.APIKey.ID, newer.APIKey.ID} {
			noError(t, f.auth.RevokeAPIKey(t.Context(), who, ref, id))
		}
		f.ageTerminal(t, "api_keys", old.APIKey.ID)
		invite, err := f.auth.CreateInvitation(t.Context(), who, ref, iam.NewInvitation{Role: f.reader})
		noError(t, err)
		noError(t, f.auth.RevokeInvitation(t.Context(), who, ref, invite.Invitation.ID))
		f.ageTerminal(t, "group_invite_links", invite.Invitation.ID)
		before, err := f.auth.ListAPIKeys(t.Context(), ref, iam.PageRequest{})
		noError(t, err)
		if len(before.Items) != 2 {
			t.Fatal("terminal inspection rows disappeared before retention sweep")
		}
		f.retrySweep(t, fleet, "authkit_cleanup_expired_auth_state", "")
		after, err := f.auth.ListAPIKeys(t.Context(), ref, iam.PageRequest{})
		noError(t, err)
		if len(after.Items) != 1 || after.Items[0].ID != newer.APIKey.ID {
			t.Fatal("retention removed a recent key or retained an expired terminal key")
		}
		invites, err := f.auth.ListInvitations(t.Context(), ref, iam.PageRequest{})
		noError(t, err)
		if len(invites.Items) != 0 {
			t.Fatal("expired terminal invitation was not removed")
		}
	})
	t.Run("AK-J32-C03_live_credentials_and_pending_recovery_survive_sweeps", func(t *testing.T) {
		var cleanup atomic.Int32
		f := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) {
			d.OnPurge = func(context.Context, iam.UserDeletion) error { cleanup.Add(1); return nil }
		}))
		fleet := f.startFleet(t)
		key, _, _ := f.key(t)
		pat, _, _ := f.personal(t, f.read)
		u := f.user(t)
		session := f.signIn(t, u)
		recoverable := f.user(t)
		rows, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{recoverable.ID})
		goodBatch(t, rows, err)
		f.retrySweep(t, fleet, "authkit_cleanup_expired_auth_state", "")
		f.retrySweep(t, fleet, "authkit_account_delete_due", authtest.Issuer)
		_, err = f.auth.ResolveAPIKey(t.Context(), key.Secret)
		noError(t, err)
		_, err = f.auth.ResolvePersonalAccessToken(t.Context(), pat.Secret)
		noError(t, err)
		cl, err := f.auth.Verify(t.Context(), session.AccessToken)
		noError(t, err)
		noError(t, f.auth.CheckSession(t.Context(), cl))
		kept, err := f.auth.User(t.Context(), iam.UserByID(recoverable.ID), authkit.IncludeDeleted())
		noError(t, err)
		if kept.DeletedAt == nil || cleanup.Load() != 0 {
			t.Fatal("cleanup crossed a live recovery window")
		}
	})
	t.Run("AK-J32-C04_successive_cleanup_cohorts_and_duplicate_jobs_converge", func(t *testing.T) {
		f := newFixture(t)
		fleet := f.startFleet(t)
		f.retrySweep(t, fleet, "authkit_cleanup_expired_auth_state", "")
		live, group, who := f.key(t)
		ref := iam.GroupByID(group.ID)
		// Small independent cohorts exercise repeated progress and safety.
		// A private SQL batch-size stress benchmark is not a day-one golden.
		for cohort := range 2 {
			for n := range 3 {
				key, err := f.auth.CreateAPIKey(t.Context(), who, ref, iam.NewAPIKey{Name: fmt.Sprintf("terminal-%d-%d", cohort, n), Role: f.reader})
				noError(t, err)
				noError(t, f.auth.RevokeAPIKey(t.Context(), who, ref, key.APIKey.ID))
				f.ageTerminal(t, "api_keys", key.APIKey.ID)
			}
			f.retrySweep(t, fleet, "authkit_cleanup_expired_auth_state", "")
			page, err := f.auth.ListAPIKeys(t.Context(), ref, iam.PageRequest{})
			noError(t, err)
			if len(page.Items) != 1 || page.Items[0].ID != live.APIKey.ID {
				t.Fatal("successive cleanup cohort lost live data or made no progress")
			}
		}
		f.retrySweep(t, fleet, "authkit_cleanup_expired_auth_state", "")
		_, err := f.auth.ResolveAPIKey(t.Context(), live.Secret)
		noError(t, err)
	})
	t.Run("AK-J32-C05_restart_catches_up_due_accounts_without_a_new_timer", func(t *testing.T) {
		var calls atomic.Int32
		f := newFixture(t, authtest.WithDeps(func(d *authkit.Deps) {
			d.OnPurge = func(context.Context, iam.UserDeletion) error { calls.Add(1); return nil }
		}))
		created := time.Now().Add(-60 * 24 * time.Hour)
		deleted := time.Now().Add(-31 * 24 * time.Hour)
		imported, err := f.auth.ImportUsers(t.Context(), []iam.ImportUser{{Username: "offlinecleanup", CreatedAt: &created, DeletedAt: &deleted}}, iam.ImportOptions{})
		noError(t, err)
		if imported.Inserted != 1 {
			t.Fatalf("offline fixture:%+v", imported)
		}
		noError(t, f.auth.Close(t.Context()))
		restarted := authtest.Replica(t, f.auth)
		noError(t, restarted.Start(context.Background()))
		eventually(t, "restart catch-up", func() bool {
			_, err := restarted.User(t.Context(), iam.UserByID(imported.Rows[0].UserID), authkit.IncludeDeleted())
			if errors.Is(err, iam.ErrUserNotFound) {
				return true
			}
			noError(t, err)
			return false
		})
		if calls.Load() != 1 {
			t.Fatalf("restart cleanup effects=%d", calls.Load())
		}
	})
	t.Run("AK-J32-C06_alias_and_history_retention_do_not_change_live_authority", func(t *testing.T) {
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.Username.Renames = true
			c.Username.RenameInterval = -1
			c.Username.FormerNames = authkit.FormerNamesConfig{Mode: authkit.FormerNamesFinite, Duration: time.Hour}
			c.EventRetention = time.Hour
			c.SessionEventRetention = time.Hour
		}))
		clock := testclock.Wall()
		testclock.Use(f.auth, clock.Now)
		fleet := f.startFleet(t)
		f.retrySweep(t, fleet, "authkit_cleanup_expired_auth_state", "")
		u := f.user(t)
		session := f.signIn(t, u)
		who := f.identity(t, session.AccessToken)
		name := "currentalias"
		_, err := f.auth.UpdateUser(t.Context(), who, u.ID, iam.UserUpdate{Username: &name})
		noError(t, err)
		alias, err := f.auth.ResolveUsername(t.Context(), u.Username)
		noError(t, err)
		if alias.ID != u.ID {
			t.Fatal("live alias resolved another identity")
		}
		before, err := f.auth.ListSessionEvents(t.Context(), u.ID, iam.SessionEventQuery{})
		noError(t, err)
		if len(before.Items) == 0 {
			t.Fatal("history fixture had no sign-in event")
		}
		_, err = f.pool.Exec(t.Context(), "UPDATE "+pgx.Identifier{f.schema, "session_events"}.Sanitize()+" SET occurred_at=statement_timestamp()-interval '2 hours' WHERE user_id=$1", u.ID)
		noError(t, err)
		clock.Advance(2 * time.Hour)
		_, err = f.auth.ResolveUsername(t.Context(), u.Username)
		if !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatal("expired alias remained authoritative before maintenance")
		}
		f.retrySweep(t, fleet, "authkit_cleanup_expired_auth_state", "")
		history, err := f.auth.ListSessionEvents(t.Context(), u.ID, iam.SessionEventQuery{})
		noError(t, err)
		if len(history.Items) != 0 {
			t.Fatal("retained session history survived its cleanup deadline")
		}
		events, err := f.auth.ListEvents(t.Context(), iam.EventQuery{})
		noError(t, err)
		if len(events.Events) != 0 {
			t.Fatal("expired retained-log history became visible")
		}
		cl, err := f.auth.Verify(t.Context(), session.AccessToken)
		noError(t, err)
		noError(t, f.auth.CheckSession(t.Context(), cl))
	})
}
