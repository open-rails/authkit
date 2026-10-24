package critical_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testclock"
	"github.com/open-rails/helpers/eventlog"
)

func TestCriticalRetainedEvents(t *testing.T) {
	t.Run("AK-J26-C01_commit_order_and_rollback_never_create_a_skip_window", func(t *testing.T) {
		f := newFixture(t)
		initial, err := f.auth.ListEvents(t.Context(), iam.EventQuery{Types: []string{"user.registered"}})
		noError(t, err)
		tx, err := f.pool.Begin(t.Context())
		noError(t, err)
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		first, err := f.auth.CreateUser(t.Context(), iam.NewUser{Email: "first-commit@example.com", Username: "firstcommit", EmailVerified: true}, authkit.InTx(tx))
		noError(t, err)
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		second, err := f.auth.CreateUser(ctx, iam.NewUser{Email: "second-commit@example.com", Username: "secondcommit", EmailVerified: true})
		noError(t, err)
		visible, err := f.auth.ListEvents(t.Context(), iam.EventQuery{After: initial.NextCursor, Types: []string{"user.registered"}})
		noError(t, err)
		if len(visible.Events) != 1 || visible.Events[0].UserID != second.ID {
			t.Fatal("reader exposed an uncommitted change or lost the committed overtaker")
		}
		noError(t, tx.Commit(t.Context()))
		after, err := f.auth.ListEvents(t.Context(), iam.EventQuery{After: visible.NextCursor, Types: []string{"user.registered"}})
		noError(t, err)
		if len(after.Events) != 1 || after.Events[0].UserID != first.ID {
			t.Fatal("later commit was skipped after the reader advanced")
		}
		rollback, err := f.pool.Begin(t.Context())
		noError(t, err)
		t.Cleanup(func() { _ = rollback.Rollback(context.Background()) })
		lost, err := f.auth.CreateUser(t.Context(), iam.NewUser{Username: "rollbackevent", Email: "rollback-event@example.com"}, authkit.InTx(rollback))
		noError(t, err)
		noError(t, rollback.Rollback(t.Context()))
		empty, err := f.auth.ListEvents(t.Context(), iam.EventQuery{After: after.NextCursor, Types: []string{"user.registered"}})
		noError(t, err)
		for _, event := range empty.Events {
			if event.UserID == lost.ID {
				t.Fatal("rolled-back state published an event")
			}
		}
	})
	t.Run("AK-J26-C02_filtered_pages_advance_in_committed_order", func(t *testing.T) {
		f := newFixture(t)
		var expected []string
		for range 3 {
			expected = append(expected, f.user(t).ID)
		}
		q := iam.EventQuery{Types: []string{"user.registered"}, Limit: 1}
		var got []string
		seen := map[string]bool{}
		for range 4 {
			page, err := f.auth.ListEvents(t.Context(), q)
			noError(t, err)
			if page.NextCursor == "" {
				t.Fatal("page omitted its reader-owned cursor")
			}
			for _, event := range page.Events {
				if event.Type != iam.EventUserRegistered || seen[event.ID] {
					t.Fatal("filter admitted another event or duplicate")
				}
				seen[event.ID] = true
				got = append(got, event.UserID)
			}
			q.After = page.NextCursor
			if !page.HasMore {
				break
			}
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("filtered order=%v want%v", got, expected)
		}
		last, err := f.auth.ListEvents(t.Context(), q)
		noError(t, err)
		if len(last.Events) != 0 || last.HasMore || last.NextCursor == "" {
			t.Fatal("exhausted reader lost its reusable cursor")
		}
	})
	t.Run("AK-J26-C03_embedded_and_HTTP_reader_have_the_same_envelope", func(t *testing.T) {
		f := newFixture(t)
		reader := f.user(t)
		authtest.GrantRole(t, f.auth, iam.RootGroup(), iam.UserSubject(reader.ID), f.rootReader)
		session := f.signIn(t, reader)
		f.user(t)
		remote, err := authkit.NewRemoteEventReader(authkit.RemoteEventConfig{BaseURL: f.server.URL + f.auth.APIBase(), HTTPClient: f.server.Client(), Headers: http.Header{"Authorization": {"Bearer " + session.AccessToken}}})
		noError(t, err)
		query := eventlog.Query{Types: []string{"user.registered"}, Limit: 50}
		local, err := f.auth.EventReader().ListEvents(t.Context(), query)
		noError(t, err)
		wire, err := remote.ListEvents(t.Context(), query)
		noError(t, err)
		if !reflect.DeepEqual(local, wire) {
			t.Fatal("embedded and HTTP event envelopes or cursors diverged")
		}
		for _, event := range wire.Events {
			if event.Source != "authkit" || event.Scope != f.tenant.String() || event.Version != 1 || event.Subject.Type != "user" || event.Subject.ID == "" {
				t.Fatal("shared event envelope lost source,scope or subject")
			}
		}
	})
	t.Run("AK-J26-C04_tenant_permissions_and_cursor_scope_are_independent", func(t *testing.T) {
		f := newFixture(t)
		reader := f.user(t)
		authtest.GrantRole(t, f.auth, iam.GroupByID(f.tenant.String()), iam.UserSubject(reader.ID), f.tenantReader)
		session := f.signIn(t, reader)
		f.call(t, "GET", "/events", session.AccessToken, nil).want(t, http.StatusOK, "")
		f.call(t, "GET", "/events?authority=true", session.AccessToken, nil).want(t, http.StatusForbidden, "forbidden")
		otherID := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: otherID}))
		other, err := f.auth.ForTenant(t.Context(), otherID)
		noError(t, err)
		server := httptest.NewServer(other.Handler())
		t.Cleanup(server.Close)
		g := &fixture{auth: other, server: server}
		g.call(t, "GET", "/events", session.AccessToken, nil).want(t, http.StatusForbidden, "forbidden")
		page, err := f.auth.ListEvents(t.Context(), iam.EventQuery{})
		noError(t, err)
		_, err = other.ListEvents(t.Context(), iam.EventQuery{After: page.NextCursor})
		if err == nil {
			t.Fatal("a foreign cursor selected another directory")
		}
		noError(t, f.auth.RemoveGroupMember(t.Context(), iam.SystemIdentity(), iam.GroupByID(f.tenant.String()), iam.UserSubject(reader.ID)))
		f.call(t, "GET", "/events", session.AccessToken, nil).want(t, http.StatusForbidden, "forbidden")
	})
	t.Run("AK-J26-C05_empty_malformed_and_expired_cursors_are_explicit", func(t *testing.T) {
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) { c.EventRetention = time.Hour }))
		clock := testclock.Wall()
		testclock.Use(f.auth, clock.Now)
		empty, err := f.auth.ListEvents(t.Context(), iam.EventQuery{Types: []string{"future.unknown.type"}})
		noError(t, err)
		if len(empty.Events) != 0 || empty.NextCursor == "" {
			t.Fatal("empty filtered stream has no progress cursor")
		}
		_, err = f.auth.ListEvents(t.Context(), iam.EventQuery{After: "not-a-cursor"})
		if err == nil {
			t.Fatal("malformed cursor was accepted")
		}
		f.user(t)
		first, err := f.auth.ListEvents(t.Context(), iam.EventQuery{Types: []string{"user.registered"}})
		noError(t, err)
		f.user(t)
		clock.Advance(2 * time.Hour)
		_, err = f.auth.ListEvents(t.Context(), iam.EventQuery{After: first.NextCursor, Types: []string{"user.registered"}})
		if !errors.Is(err, iam.ErrEventCursorExpired) {
			t.Fatalf("missing expired history did not require resync: %v", err)
		}
	})
	t.Run("AK-J26-C06_readers_do_not_ack_source_and_restore_invalidates_cursor", func(t *testing.T) {
		f := newFixture(t)
		f.user(t)
		one, err := f.auth.ListEvents(t.Context(), iam.EventQuery{})
		noError(t, err)
		two, err := f.auth.ListEvents(t.Context(), iam.EventQuery{})
		noError(t, err)
		if !reflect.DeepEqual(one, two) {
			t.Fatal("a reader changed or consumed retained source facts")
		}
		// This is the documented restore operation on the isolated fixture,
		// not an application mutation or a source-owned consumer ACK.
		_, err = f.pool.Exec(t.Context(), "UPDATE "+pgx.Identifier{f.schema, "event_log_instance"}.Sanitize()+" SET epoch=gen_random_uuid() WHERE singleton")
		noError(t, err)
		restored := authtest.Replica(t, f.auth)
		_, err = restored.ListEvents(t.Context(), iam.EventQuery{After: one.NextCursor})
		if !errors.Is(err, iam.ErrEventCursorExpired) {
			t.Fatalf("restored incarnation reused an old cursor: %v", err)
		}
	})
}
