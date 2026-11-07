package critical_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

func TestCriticalSessionHistoryImport(t *testing.T) {
	rdb := realRedis(t)
	redisDep := authtest.WithDeps(func(d *authkit.Deps) { d.Redis = rdb })
	f := newFixture(t, redisDep)
	entry := func(userID, id string) iam.ImportSessionEvent {
		return iam.ImportSessionEvent{UserID: userID, ID: id, Kind: iam.SessionEventCreated,
			OccurredAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond),
			Method:     "legacy-logins", IP: "192.0.2.47", UserAgent: "legacy browser"}
	}
	wantRow := func(t *testing.T, result iam.ImportSessionEventsResult, index int, status iam.ImportSessionEventStatus, reason iam.ImportSessionEventReason) {
		t.Helper()
		if index >= len(result.Rows) || result.Rows[index] != (iam.ImportSessionEventRow{Index: index, Status: status, Reason: reason}) {
			t.Fatalf("row %d: %+v, want %s/%s", index, result, status, reason)
		}
	}
	t.Run("AK-J05-C07_imported_history_lists_with_native_without_account_or_session_changes", func(t *testing.T) {
		u := f.user(t)
		f.signIn(t, u)
		before, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		sessions, err := f.auth.Sessions(t.Context(), u.ID)
		noError(t, err)
		events, err := f.auth.ListEvents(t.Context(), iam.EventQuery{})
		noError(t, err)
		messages := f.out.Messages("", "")
		native, err := f.auth.ListSessionEvents(t.Context(), u.ID, iam.SessionEventQuery{})
		noError(t, err)
		if len(native.Items) != 1 || native.Items[0].SessionID == nil {
			t.Fatalf("native sign-in missing: %+v", native)
		}
		success := entry(u.ID, "legacy:1")
		success.Issuer = "doujins.com"
		failure := entry(u.ID, "legacy:2")
		failure.Kind, failure.Method, failure.Reason, failure.IP = iam.SessionEventFailed, "", "legacy-logins:bad-password", "2001:db8::47"
		failure.OccurredAt = success.OccurredAt.Add(-time.Minute)
		rows := []iam.ImportSessionEvent{success, failure, success}
		got, err := f.auth.ImportSessionEvents(t.Context(), rows)
		noError(t, err)
		wantRow(t, got, 0, iam.SessionEventImported, "")
		wantRow(t, got, 1, iam.SessionEventImported, "")
		wantRow(t, got, 2, iam.SessionEventDuplicate, "")
		// An acknowledged retry and a retry with changed fields preserve the original.
		rows[0].Issuer, rows[0].IP, rows[0].Kind = "hentai0.com", "192.0.2.99", iam.SessionEventFailed
		got, err = f.auth.ImportSessionEvents(t.Context(), rows)
		noError(t, err)
		for i := range rows {
			wantRow(t, got, i, iam.SessionEventDuplicate, "")
		}
		page, err := f.auth.ListSessionEvents(t.Context(), u.ID, iam.SessionEventQuery{Page: iam.PageRequest{Limit: 2}})
		noError(t, err)
		if len(page.Items) != 2 || page.Next == "" || !reflect.DeepEqual(page.Items[0], native.Items[0]) {
			t.Fatalf("history page: %+v", page)
		}
		wantSuccess := iam.SessionEvent{Kind: success.Kind, OccurredAt: success.OccurredAt, Issuer: success.Issuer,
			Method: &success.Method, IP: &success.IP, UserAgent: &success.UserAgent}
		imported := page.Items[1]
		imported.OccurredAt = imported.OccurredAt.UTC()
		if !reflect.DeepEqual(imported, wantSuccess) {
			t.Fatalf("import changed: %+v, want %+v", page.Items[1], wantSuccess)
		}
		next, err := f.auth.ListSessionEvents(t.Context(), u.ID, iam.SessionEventQuery{Page: iam.PageRequest{Cursor: page.Next}})
		noError(t, err)
		wantFailure := iam.SessionEvent{Kind: failure.Kind, OccurredAt: failure.OccurredAt, Issuer: f.cfg.Token.Issuer,
			Reason: &failure.Reason, IP: &failure.IP, UserAgent: &failure.UserAgent}
		if len(next.Items) != 1 || next.Next != "" {
			t.Fatalf("failure page: %+v", next)
		}
		imported = next.Items[0]
		imported.OccurredAt = imported.OccurredAt.UTC()
		if !reflect.DeepEqual(imported, wantFailure) {
			t.Fatalf("failure page: %+v, want %+v", next, wantFailure)
		}
		filtered, err := f.auth.ListSessionEvents(t.Context(), u.ID, iam.SessionEventQuery{Kinds: []iam.SessionEventKind{iam.SessionEventFailed}})
		noError(t, err)
		if !reflect.DeepEqual(filtered.Items, next.Items) {
			t.Fatalf("kind filter = %+v", filtered)
		}
		after, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		afterSessions, err := f.auth.Sessions(t.Context(), u.ID)
		noError(t, err)
		afterEvents, err := f.auth.ListEvents(t.Context(), iam.EventQuery{})
		noError(t, err)
		if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(sessions, afterSessions) ||
			!reflect.DeepEqual(events, afterEvents) || !reflect.DeepEqual(messages, f.out.Messages("", "")) {
			t.Fatal("history import changed account, live sessions, events or sent messages")
		}
		// A stable key belongs to an account, not globally to the source.
		other := f.user(t)
		success.UserID = other.ID
		got, err = f.auth.ImportSessionEvents(t.Context(), []iam.ImportSessionEvent{success})
		noError(t, err)
		wantRow(t, got, 0, iam.SessionEventImported, "")
		untouched, err := f.auth.User(t.Context(), iam.UserByID(other.ID))
		noError(t, err)
		live, err := f.auth.Sessions(t.Context(), other.ID)
		noError(t, err)
		if untouched.LastLogin != nil || len(live) != 0 {
			t.Fatal("import granted a never-signed-in account a session or last login")
		}
	})
	t.Run("AK-J05-C08_history_refuses_invalid_unknown_deleted_and_foreign_entries_individually", func(t *testing.T) {
		u, deleted := f.user(t), f.user(t)
		deletedRows, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{deleted.ID})
		noError(t, err)
		if len(deletedRows) != 1 || deletedRows[0].Err != nil {
			t.Fatalf("delete fixture: %+v", deletedRows)
		}
		otherTenant := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: otherTenant, Slug: "history-other"}))
		other, err := f.auth.ForTenant(t.Context(), otherTenant)
		noError(t, err)
		foreign, err := other.CreateUser(t.Context(), iam.NewUser{Username: "foreignhistory"})
		noError(t, err)
		rows := []iam.ImportSessionEvent{entry(iam.NewTenantID().String(), "absent"), entry(deleted.ID, "deleted"), entry(foreign.ID, "foreign"), entry(u.ID, "valid")}
		got, err := f.auth.ImportSessionEvents(t.Context(), rows)
		noError(t, err)
		wantRow(t, got, 0, iam.SessionEventRefused, iam.SessionEventUnknownAccount)
		wantRow(t, got, 1, iam.SessionEventRefused, iam.SessionEventDeletedAccount)
		wantRow(t, got, 2, iam.SessionEventRefused, iam.SessionEventUnknownAccount)
		wantRow(t, got, 3, iam.SessionEventImported, "")
		page, err := other.ListSessionEvents(t.Context(), foreign.ID, iam.SessionEventQuery{})
		noError(t, err)
		if len(page.Items) != 0 {
			t.Fatal("refused foreign entry was inserted")
		}
		mutations := []struct {
			name string
			edit func(*iam.ImportSessionEvent)
		}{
			{"account_id", func(e *iam.ImportSessionEvent) { e.UserID = "not-a-uuid" }},
			{"missing_id", func(e *iam.ImportSessionEvent) { e.ID = " " }},
			{"id_length", func(e *iam.ImportSessionEvent) { e.ID = strings.Repeat("x", 257) }},
			{"kind", func(e *iam.ImportSessionEvent) { e.Kind = iam.SessionEventRevoked }},
			{"missing_time", func(e *iam.ImportSessionEvent) { e.OccurredAt = time.Time{} }},
			{"future_time", func(e *iam.ImportSessionEvent) { e.OccurredAt = time.Now().Add(time.Hour) }},
			{"issuer_length", func(e *iam.ImportSessionEvent) { e.Issuer = strings.Repeat("x", 2049) }},
			{"blank_issuer", func(e *iam.ImportSessionEvent) { e.Issuer = " " }},
			{"missing_source", func(e *iam.ImportSessionEvent) { e.Method, e.Reason = "", " " }},
			{"method_length", func(e *iam.ImportSessionEvent) { e.Method = strings.Repeat("x", 257) }},
			{"reason_length", func(e *iam.ImportSessionEvent) { e.Reason = strings.Repeat("x", 257) }},
			{"agent_length", func(e *iam.ImportSessionEvent) { e.UserAgent = strings.Repeat("x", 4097) }},
			{"nul", func(e *iam.ImportSessionEvent) { e.UserAgent = "bad\x00agent" }},
			{"utf8", func(e *iam.ImportSessionEvent) { e.Method = "\xff" }},
			{"ip", func(e *iam.ImportSessionEvent) { e.IP = "192.0.2.1/24" }},
			{"packed_ip", func(e *iam.ImportSessionEvent) { e.IP = string([]byte{192, 0, 2, 47}) }},
			{"ip_zone", func(e *iam.ImportSessionEvent) { e.IP = "fe80::1%eth0" }},
		}
		for _, test := range mutations {
			t.Run(test.name, func(t *testing.T) {
				invalid := entry(u.ID, test.name)
				test.edit(&invalid)
				valid := entry(u.ID, "after-"+test.name)
				got, err := f.auth.ImportSessionEvents(t.Context(), []iam.ImportSessionEvent{invalid, valid})
				noError(t, err)
				wantRow(t, got, 0, iam.SessionEventRefused, iam.SessionEventInvalid)
				wantRow(t, got, 1, iam.SessionEventImported, "")
			})
		}
	})
	t.Run("AK-J05-C09_concurrent_history_replay_inserts_once", func(t *testing.T) {
		u := f.user(t)
		rows := []iam.ImportSessionEvent{entry(u.ID, "concurrent")}
		var results [2]iam.ImportSessionEventsResult
		var errs [2]error
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range results {
			wg.Go(func() {
				<-start
				results[i], errs[i] = f.auth.ImportSessionEvents(t.Context(), rows)
			})
		}
		close(start)
		wg.Wait()
		counts := map[iam.ImportSessionEventStatus]int{}
		for i, result := range results {
			noError(t, errs[i])
			if len(result.Rows) != 1 {
				t.Fatalf("concurrent result: %+v", result)
			}
			counts[result.Rows[0].Status]++
		}
		if counts[iam.SessionEventImported] != 1 || counts[iam.SessionEventDuplicate] != 1 {
			t.Fatalf("concurrent outcomes: %+v", results)
		}
		page, err := f.auth.ListSessionEvents(t.Context(), u.ID, iam.SessionEventQuery{})
		noError(t, err)
		if len(page.Items) != 1 {
			t.Fatalf("concurrent import forked history: %+v", page)
		}
	})
	t.Run("AK-J05-C10_history_import_obeys_configured_and_unlimited_retention", func(t *testing.T) {
		for _, retention := range []time.Duration{0, 24 * time.Hour, -1} {
			t.Run(retention.String(), func(t *testing.T) {
				f := newFixture(t, redisDep, authtest.WithConfig(func(c *authkit.Config) { c.SessionEventRetention = retention }))
				u := f.user(t)
				old, recent, middle := entry(u.ID, "old"), entry(u.ID, "recent"), entry(u.ID, "middle")
				old.OccurredAt = time.Now().Add(-366 * 24 * time.Hour)
				middle.OccurredAt = time.Now().Add(-48 * time.Hour)
				recent.IP, recent.UserAgent = "", ""
				got, err := f.auth.ImportSessionEvents(t.Context(), []iam.ImportSessionEvent{old, recent, middle})
				noError(t, err)
				wantOld := iam.SessionEventRefused
				if retention < 0 {
					wantOld = iam.SessionEventImported
					wantRow(t, got, 0, wantOld, "")
				} else {
					wantRow(t, got, 0, wantOld, iam.SessionEventTooOld)
				}
				wantRow(t, got, 1, iam.SessionEventImported, "")
				if retention > 0 {
					wantRow(t, got, 2, iam.SessionEventRefused, iam.SessionEventTooOld)
				} else {
					wantRow(t, got, 2, iam.SessionEventImported, "")
				}
				page, err := f.auth.ListSessionEvents(t.Context(), u.ID, iam.SessionEventQuery{})
				noError(t, err)
				wantCount := 2
				if retention < 0 {
					wantCount = 3
				} else if retention > 0 {
					wantCount = 1
				}
				if len(page.Items) != wantCount || page.Items[0].IP != nil || page.Items[0].UserAgent != nil {
					t.Fatalf("retention history: %+v", page)
				}
			})
		}
	})
	t.Run("AK-J05-C11_history_batch_bound_and_unsupported_options_write_nothing", func(t *testing.T) {
		u := f.user(t)
		rows := make([]iam.ImportSessionEvent, 1001)
		for i := range rows {
			rows[i] = entry(u.ID, "bounded")
		}
		got, err := f.auth.ImportSessionEvents(t.Context(), rows)
		if e, ok := iam.AsError(err); !ok || e.Code() != "invalid_request" || len(got.Rows) != 0 {
			t.Fatalf("oversized import: %+v, %v", got, err)
		}
		page, err := f.auth.ListSessionEvents(t.Context(), u.ID, iam.SessionEventQuery{})
		noError(t, err)
		if len(page.Items) != 0 {
			t.Fatal("oversized batch wrote history")
		}
		tx, err := f.pool.Begin(t.Context())
		noError(t, err)
		_, err = f.auth.ImportSessionEvents(t.Context(), rows[:1], authkit.InTx(tx))
		if err == nil {
			t.Fatal("unsupported transaction option accepted")
		}
		noError(t, tx.Rollback(t.Context()))
		got, err = f.auth.ImportSessionEvents(t.Context(), rows[:1000])
		noError(t, err)
		if len(got.Rows) != 1000 {
			t.Fatalf("boundary import returned %d rows", len(got.Rows))
		}
		wantRow(t, got, 0, iam.SessionEventImported, "")
		for i := 1; i < len(got.Rows); i++ {
			wantRow(t, got, i, iam.SessionEventDuplicate, "")
		}
		got, err = f.auth.ImportSessionEvents(t.Context(), nil)
		noError(t, err)
		if len(got.Rows) != 0 {
			t.Fatalf("empty batch: %+v", got)
		}
		authority := authtest.Replica(t, f.auth, authtest.WithConfig(func(c *authkit.Config) { c.DefaultTenantID = iam.TenantID{} }))
		got, err = authority.ImportSessionEvents(t.Context(), rows[:1])
		if !errors.Is(err, iam.ErrTenantRequired) || len(got.Rows) != 0 {
			t.Fatalf("unbound authority imported account history: %+v, %v", got, err)
		}
	})
	t.Run("AK-J05-C12_history_partial_database_failure_and_cancellation_retry_safely", func(t *testing.T) {
		u := f.user(t)
		rows := []iam.ImportSessionEvent{entry(u.ID, "committed"), entry(u.ID, "database-failure"), entry(u.ID, "unprocessed")}
		function := pgx.Identifier{f.schema, "refuse_import_fixture"}.Sanitize()
		table := pgx.Identifier{f.schema, "session_events"}.Sanitize()
		_, err := f.pool.Exec(t.Context(), "CREATE FUNCTION "+function+"() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.import_id = 'database-failure' THEN RAISE EXCEPTION 'injected storage failure'; END IF; RETURN NEW; END $$")
		noError(t, err)
		_, err = f.pool.Exec(t.Context(), "CREATE TRIGGER refuse_import_fixture BEFORE INSERT ON "+table+" FOR EACH ROW EXECUTE FUNCTION "+function+"()")
		noError(t, err)
		got, err := f.auth.ImportSessionEvents(t.Context(), rows)
		if err == nil || len(got.Rows) != 1 {
			t.Fatalf("database failure hid progress: %+v, %v", got, err)
		}
		wantRow(t, got, 0, iam.SessionEventImported, "")
		page, err := f.auth.ListSessionEvents(t.Context(), u.ID, iam.SessionEventQuery{})
		noError(t, err)
		if len(page.Items) != 1 {
			t.Fatalf("unprocessed rows became visible: %+v", page)
		}
		_, err = f.pool.Exec(t.Context(), "DROP TRIGGER refuse_import_fixture ON "+table)
		noError(t, err)
		cancelled, cancel := context.WithCancel(t.Context())
		cancel()
		got, err = f.auth.ImportSessionEvents(cancelled, rows)
		if !errors.Is(err, context.Canceled) || len(got.Rows) != 0 {
			t.Fatalf("cancelled import: %+v, %v", got, err)
		}
		got, err = f.auth.ImportSessionEvents(t.Context(), rows)
		noError(t, err)
		wantRow(t, got, 0, iam.SessionEventDuplicate, "")
		wantRow(t, got, 1, iam.SessionEventImported, "")
		wantRow(t, got, 2, iam.SessionEventImported, "")
	})
	t.Run("AK-J05-C13_history_import_serializes_with_account_deletion", func(t *testing.T) {
		for _, first := range []string{"import", "delete"} {
			t.Run(first+"_first", func(t *testing.T) {
				u := f.user(t)
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				defer cancel()
				gate, err := f.pool.Begin(ctx)
				noError(t, err)
				defer gate.Rollback(context.Background())
				var gatePID int32
				noError(t, gate.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&gatePID))
				// A trigger pauses the first real operation after its account
				// check, while pg_blocking_pids proves the second is waiting.
				_, err = gate.Exec(ctx, "SELECT pg_advisory_xact_lock(476, 1)")
				noError(t, err)
				function := pgx.Identifier{f.schema, "pause_history_race"}.Sanitize()
				table := pgx.Identifier{f.schema, "session_events"}.Sanitize()
				event := "INSERT"
				condition := "NEW.import_id = 'deletion-race'"
				if first == "delete" {
					table = pgx.Identifier{f.schema, "users"}.Sanitize()
					event = "UPDATE"
					condition = "OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL"
				}
				_, err = f.pool.Exec(ctx, "CREATE OR REPLACE FUNCTION "+function+"() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF "+condition+" THEN PERFORM pg_advisory_xact_lock(476, 1); END IF; RETURN NEW; END $$")
				noError(t, err)
				_, err = f.pool.Exec(ctx, "CREATE TRIGGER pause_history_race BEFORE "+event+" ON "+table+" FOR EACH ROW EXECUTE FUNCTION "+function+"()")
				noError(t, err)
				defer func() {
					cancel()
					_ = gate.Rollback(context.Background())
					cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
					defer done()
					_, err := f.pool.Exec(cleanup, "DROP TRIGGER pause_history_race ON "+table)
					if err != nil {
						t.Error(err)
					}
				}()
				type importResult struct {
					result iam.ImportSessionEventsResult
					err    error
				}
				type deleteResult struct {
					rows []iam.OpResult
					err  error
				}
				imports, deletions := make(chan importResult, 1), make(chan deleteResult, 1)
				importHistory := func() {
					result, err := f.auth.ImportSessionEvents(ctx, []iam.ImportSessionEvent{entry(u.ID, "deletion-race")})
					imports <- importResult{result, err}
				}
				deleteAccount := func() {
					rows, err := f.auth.DeleteUsers(ctx, iam.SystemIdentity(), []string{u.ID})
					deletions <- deleteResult{rows, err}
				}
				if first == "import" {
					go importHistory()
				} else {
					go deleteAccount()
				}
				var firstPID int32
				eventually(t, first+" paused inside its database trigger", func() bool {
					err := f.pool.QueryRow(ctx, "SELECT pid FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))", gatePID).Scan(&firstPID)
					if errors.Is(err, pgx.ErrNoRows) {
						return false
					}
					noError(t, err)
					return true
				})
				if first == "import" {
					go deleteAccount()
				} else {
					go importHistory()
				}
				eventually(t, "second operation blocked on the first account lock", func() bool {
					var blocked bool
					noError(t, f.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))", firstPID).Scan(&blocked))
					return blocked
				})
				noError(t, gate.Commit(ctx))
				imported, deleted := <-imports, <-deletions
				noError(t, imported.err)
				noError(t, deleted.err)
				if len(deleted.rows) != 1 || deleted.rows[0].Err != nil {
					t.Fatalf("concurrent deletion: %+v", deleted)
				}
				wantCount := 0
				if first == "import" {
					wantRow(t, imported.result, 0, iam.SessionEventImported, "")
					wantCount = 1
				} else {
					wantRow(t, imported.result, 0, iam.SessionEventRefused, iam.SessionEventDeletedAccount)
				}
				page, err := f.auth.ListSessionEvents(ctx, u.ID, iam.SessionEventQuery{})
				noError(t, err)
				if len(page.Items) != wantCount {
					t.Fatalf("history crossed deletion: %+v", page)
				}
			})
		}
	})
}

func TestCriticalSessions(t *testing.T) {
	f := newFixture(t)
	t.Run("AK-J05-C01_concurrent_refresh_has_one_successor", func(t *testing.T) {
		u := f.user(t)
		old := f.signIn(t, u)
		if old.RefreshToken == nil {
			t.Fatal("non-cookie login omitted refresh token")
		}
		body := map[string]string{"grant_type": "refresh_token", "refresh_token": *old.RefreshToken}
		responses := make([]response, 2)
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range responses {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				responses[i], errs[i] = f.request(t.Context(), "POST", "/token", "", body)
			}()
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			noError(t, err)
		}
		one, two := tokensFrom(t, responses[0], u.ID), tokensFrom(t, responses[1], u.ID)
		if one.RefreshToken == nil || two.RefreshToken == nil || *one.RefreshToken != *two.RefreshToken || *one.RefreshToken == *old.RefreshToken {
			t.Fatal("concurrent refresh forked or failed to rotate its successor")
		}
		c1, err := f.auth.Verify(t.Context(), one.AccessToken)
		noError(t, err)
		c2, err := f.auth.Verify(t.Context(), two.AccessToken)
		noError(t, err)
		if c1.SessionID == "" || c1.SessionID != c2.SessionID {
			t.Fatal("refresh created independent session authority")
		}
		live, err := f.auth.Sessions(t.Context(), u.ID)
		noError(t, err)
		if len(live) != 1 || live[0].ID != c1.SessionID {
			t.Fatalf("refresh session state = %+v", live)
		}
		// Retrying the unacknowledged predecessor returns that same successor.
		retry := tokensFrom(t, f.call(t, "POST", "/token", "", body), u.ID)
		if retry.RefreshToken == nil || *retry.RefreshToken != *one.RefreshToken {
			t.Fatal("lost-response retry forked the rotation chain")
		}
	})
	t.Run("AK-J05-C02_revoke_other_then_all_sessions", func(t *testing.T) {
		u := f.user(t)
		one, two := f.signIn(t, u), f.signIn(t, u)
		other, err := f.auth.Verify(t.Context(), two.AccessToken)
		noError(t, err)
		f.call(t, "DELETE", "/me/sessions/"+other.SessionID, one.AccessToken, nil).want(t, http.StatusNoContent, "")
		f.call(t, "PATCH", "/me", two.AccessToken, map[string]string{"username": "revokedwriter"}).want(t, http.StatusUnauthorized, "session_revoked")
		f.call(t, "GET", "/me/sessions", one.AccessToken, nil).want(t, http.StatusOK, "")
		who := f.identity(t, one.AccessToken)
		_, err = f.auth.RevokeAccountSessions(t.Context(), who, u.ID)
		noError(t, err)
		for _, token := range []string{one.AccessToken, two.AccessToken} {
			claims, err := f.auth.Verify(t.Context(), token)
			noError(t, err)
			if !errors.Is(f.auth.CheckSession(t.Context(), claims), iam.ErrSessionRevoked) {
				t.Fatal("account revoke left a session usable")
			}
		}
		live, err := f.auth.Sessions(t.Context(), u.ID)
		noError(t, err)
		if len(live) != 0 {
			t.Fatal("revoked sessions remained in live listing")
		}
	})
	t.Run("AK-J05-C03_password_and_ban_retire_live_authority", func(t *testing.T) {
		u := f.user(t)
		current, other := f.signIn(t, u), f.signIn(t, u)
		const changed = "Changed-critical-password-2"
		f.call(t, "PUT", "/me/password", current.AccessToken, map[string]string{"new_password": changed}).want(t, http.StatusNoContent, "")
		f.call(t, "PATCH", "/me", other.AccessToken, map[string]string{"username": "oldcredential"}).want(t, http.StatusUnauthorized, "session_revoked")
		f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}).want(t, http.StatusUnauthorized, "invalid_credentials")
		u.Password = changed
		newTokens := f.signIn(t, u)
		noError(t, f.auth.Ban(t.Context(), iam.SystemIdentity(), u.ID, iam.Ban{}))
		claims, err := f.auth.Verify(t.Context(), newTokens.AccessToken)
		noError(t, err)
		if !errors.Is(f.auth.CheckSession(t.Context(), claims), iam.ErrSessionRevoked) {
			t.Fatal("ban preserved live authority")
		}
		f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": changed}).want(t, http.StatusUnauthorized, "user_banned")
	})
	t.Run("AK-J05-C04_stateless_signature_is_not_live_session_authority", func(t *testing.T) {
		u := f.user(t)
		tokens := f.signIn(t, u)
		claims, err := f.auth.Verify(t.Context(), tokens.AccessToken)
		noError(t, err)
		if claims.UserID != u.ID || claims.SessionID == "" {
			t.Fatal("sign-in token did not bind the expected user and session")
		}
		who := f.identity(t, tokens.AccessToken)
		noError(t, f.auth.RevokeSession(t.Context(), who, u.ID, claims.SessionID))
		// An old JWT remains cryptographically valid; privileged requests must
		// nevertheless consult the now-revoked sign-in.
		_, err = f.auth.Verify(t.Context(), tokens.AccessToken)
		noError(t, err)
		if err := f.auth.CheckSession(t.Context(), claims); !errors.Is(err, iam.ErrSessionRevoked) {
			t.Fatalf("revoked session error = %v", err)
		}
		f.call(t, "PATCH", "/me", tokens.AccessToken, map[string]string{"username": "mustnotpersist"}).want(t, http.StatusUnauthorized, "session_revoked")
		r, err := http.NewRequestWithContext(t.Context(), "GET", f.server.URL+"/identity", nil)
		noError(t, err)
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		if _, err = f.auth.Authenticator().Authenticate(r); !errors.Is(err, auth.ErrUnauthenticated) || !errors.Is(err, auth.ErrRevoked) {
			t.Fatalf("live authenticator must classify revoked authority: %v", err)
		}
		current, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if current.Username != u.Username {
			t.Fatal("refused mutation changed the public account state")
		}
	})
	t.Run("AK-J05-C06_member_checks_read_account_and_session_once_per_call", func(t *testing.T) {
		f, log := newTracedFixture(t)
		g, _, _ := f.ownedGroup(t)
		refs := []iam.GroupRef{iam.RootGroup(), iam.GroupByID(f.tenant.String()), iam.GroupByID(g.ID)}
		request := func(ctx context.Context, token string) *http.Request {
			r, err := http.NewRequestWithContext(ctx, "GET", f.server.URL+"/member", nil)
			noError(t, err)
			r.Header.Set("Authorization", "Bearer "+token)
			return r
		}
		// The hosts' tenant member gate: a live sign-in, then its source account.
		member := func(ctx context.Context, token string) (iam.TenantActor, error) {
			verified, err := verify.AuthenticateSession(ctx, f.auth, request(ctx, token))
			if err != nil {
				return iam.TenantActor{}, err
			}
			return f.auth.ResolveTenantActor(ctx, verified)
		}
		signedIn := func(t *testing.T) (string, string, auth.Verified) {
			u := f.user(t)
			f.grant(t, g, u, f.reader)
			token := f.signIn(t, u).AccessToken
			verified, err := verify.AuthenticateSession(t.Context(), f.auth, request(t.Context(), token))
			noError(t, err)
			return u.ID, token, verified
		}
		exec := func(t *testing.T, sql string, args ...any) {
			tag, err := f.pool.Exec(t.Context(), sql, args...)
			noError(t, err)
			if tag.RowsAffected() != 1 {
				t.Fatalf("fixture update touched %d rows", tag.RowsAffected())
			}
		}
		table := func(name string) string { return pgx.Identifier{f.schema, name}.Sanitize() }

		id, token, verified := signedIn(t)
		for range 2 { // the second round runs on warm caches and connections
			var actor iam.TenantActor
			sent := log.during(t.Context(), func(ctx context.Context) {
				var err error
				actor, err = member(ctx, token)
				noError(t, err)
			})
			if actor != (iam.TenantActor{AccountID: id, TenantID: f.tenant}) {
				t.Fatalf("member resolved %+v", actor)
			}
			if len(sent) > 2 {
				t.Errorf("tenant member gate sent %d statements, want at most 2: %v", len(sent), sent)
			}
			var perms map[string][]iam.Perm
			sent = log.during(t.Context(), func(ctx context.Context) {
				var err error
				perms, err = f.auth.EffectivePermissions(ctx, verified.Identity(), refs)
				noError(t, err)
			})
			if len(perms[g.ID]) == 0 {
				t.Fatalf("live member lost its grant: %v", perms)
			}
			if len(sent) > 2 {
				t.Errorf("EffectivePermissions sent %d statements, want at most 2: %v", len(sent), sent)
			}
			sent = log.during(t.Context(), func(ctx context.Context) {
				ok, err := f.auth.Can(ctx, verified.Identity(), iam.GroupByID(g.ID), f.read)
				noError(t, err)
				if !ok {
					t.Fatal("live member cannot use its grant")
				}
			})
			if len(sent) > 3 {
				t.Errorf("Can sent %d statements, want at most 3: %v", len(sent), sent)
			}
		}

		// revoked is every check refusing a sign-in that no longer stands.
		revoked := func(t *testing.T, token string, verified auth.Verified) {
			t.Helper()
			if actor, err := member(t.Context(), token); !errors.Is(err, auth.ErrUnauthenticated) || !errors.Is(err, auth.ErrRevoked) || actor != (iam.TenantActor{}) {
				t.Fatalf("tenant member gate admitted %+v: %v", actor, err)
			}
			if actor, err := f.auth.ResolveTenantActor(t.Context(), verified); !errors.Is(err, auth.ErrUnauthenticated) || actor != (iam.TenantActor{}) {
				t.Fatalf("retained credential resolved %+v: %v", actor, err)
			}
			if perms, err := f.auth.EffectivePermissions(t.Context(), verified.Identity(), refs); !errors.Is(err, iam.ErrSessionRevoked) || len(perms) != 0 {
				t.Fatalf("EffectivePermissions kept %v: %v", perms, err)
			}
			if ok, err := f.auth.Can(t.Context(), verified.Identity(), iam.GroupByID(g.ID), f.read); !errors.Is(err, iam.ErrSessionRevoked) || ok {
				t.Fatalf("Can kept %v: %v", ok, err)
			}
		}
		t.Run("signed_out", func(t *testing.T) {
			_, token, verified := signedIn(t)
			f.call(t, "DELETE", "/logout", token, nil).want(t, http.StatusNoContent, "")
			revoked(t, token, verified)
		})
		t.Run("session_revoked", func(t *testing.T) {
			id, token, verified := signedIn(t)
			claims, err := f.auth.Verify(t.Context(), token)
			noError(t, err)
			noError(t, f.auth.RevokeSession(t.Context(), iam.SystemIdentity(), id, claims.SessionID))
			revoked(t, token, verified)
		})
		t.Run("session_expired", func(t *testing.T) {
			_, token, verified := signedIn(t)
			claims, err := f.auth.Verify(t.Context(), token)
			noError(t, err)
			exec(t, "UPDATE "+table("refresh_sessions")+" SET expires_at = now() - interval '1 microsecond' WHERE id = $1", claims.SessionID)
			revoked(t, token, verified)
		})
		t.Run("banned", func(t *testing.T) {
			id, token, verified := signedIn(t)
			noError(t, f.auth.Ban(t.Context(), iam.SystemIdentity(), id, iam.Ban{}))
			revoked(t, token, verified)
		})
		t.Run("deleted", func(t *testing.T) {
			id, token, verified := signedIn(t)
			results, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{id})
			noError(t, err)
			if len(results) != 1 || results[0].Err != nil {
				t.Fatalf("delete results %+v", results)
			}
			revoked(t, token, verified)
		})
		// The account checks refuse alone, before its sign-in is revoked.
		t.Run("deleted_with_sign_in_row_still_live", func(t *testing.T) {
			id, token, verified := signedIn(t)
			exec(t, "UPDATE "+table("users")+" SET deleted_at = now() WHERE id = $1", id)
			if actor, err := member(t.Context(), token); !errors.Is(err, auth.ErrRevoked) || actor != (iam.TenantActor{}) {
				t.Fatalf("tenant member gate admitted a deleted account: %+v, %v", actor, err)
			}
			if actor, err := f.auth.ResolveTenantActor(t.Context(), verified); !errors.Is(err, auth.ErrUnauthenticated) || actor != (iam.TenantActor{}) {
				t.Fatalf("deleted account resolved %+v: %v", actor, err)
			}
			if perms, err := f.auth.EffectivePermissions(t.Context(), verified.Identity(), refs); err != nil || len(perms) != 0 {
				t.Fatalf("deleted account kept %v: %v", perms, err)
			}
			if ok, err := f.auth.Can(t.Context(), verified.Identity(), iam.GroupByID(g.ID), f.read); !errors.Is(err, iam.ErrSessionRevoked) || ok {
				t.Fatalf("deleted account kept Can %v: %v", ok, err)
			}
		})
		t.Run("banned_with_sign_in_row_still_live", func(t *testing.T) {
			id, token, verified := signedIn(t)
			exec(t, "UPDATE "+table("users")+" SET banned_at = now() WHERE id = $1", id)
			if actor, err := member(t.Context(), token); !errors.Is(err, auth.ErrRevoked) || actor != (iam.TenantActor{}) {
				t.Fatalf("tenant member gate admitted a banned account: %+v, %v", actor, err)
			}
			if actor, err := f.auth.ResolveTenantActor(t.Context(), verified); !errors.Is(err, auth.ErrUnauthenticated) || actor != (iam.TenantActor{}) {
				t.Fatalf("banned account resolved %+v: %v", actor, err)
			}
			if perms, err := f.auth.EffectivePermissions(t.Context(), verified.Identity(), refs); err != nil || len(perms) != 0 {
				t.Fatalf("banned account kept %v: %v", perms, err)
			}
			if ok, err := f.auth.Can(t.Context(), verified.Identity(), iam.GroupByID(g.ID), f.read); err != nil || ok {
				t.Fatalf("banned account kept Can %v: %v", ok, err)
			}
		})
		// A sign-in stands only for its own account.
		t.Run("session_of_another_account", func(t *testing.T) {
			_, ownerToken, _ := signedIn(t)
			owner, err := f.auth.Verify(t.Context(), ownerToken)
			noError(t, err)
			intruder, _, _ := signedIn(t)
			claims := owner
			claims.UserID, claims.Subject = intruder, intruder
			if err := f.auth.CheckSession(t.Context(), claims); !errors.Is(err, iam.ErrSessionRevoked) {
				t.Fatalf("another account's sign-in kept a live session: %v", err)
			}
			minted, err := f.auth.MintAccessToken(t.Context(), intruder, iam.AccessTokenOptions{SessionID: owner.SessionID})
			noError(t, err)
			if actor, err := member(t.Context(), minted.Value); !errors.Is(err, auth.ErrRevoked) || actor != (iam.TenantActor{}) {
				t.Fatalf("tenant member gate admitted another account's sign-in: %+v, %v", actor, err)
			}
			who := iam.InSession(iam.UserIdentity(intruder), iam.SessionRef{SessionID: owner.SessionID})
			if ok, err := f.auth.Can(t.Context(), who, iam.GroupByID(g.ID), f.read); !errors.Is(err, iam.ErrSessionRevoked) || ok {
				t.Fatalf("another account's sign-in kept Can %v: %v", ok, err)
			}
			noError(t, f.auth.CheckSession(t.Context(), owner))
		})
		// PostgreSQL reads other spellings of a uuid; AuthKit compares ids only
		// in the hyphenated form and refuses the rest as no usable account.
		t.Run("non_standard_account_id", func(t *testing.T) {
			id, token, _ := signedIn(t)
			claims, err := f.auth.Verify(t.Context(), token)
			noError(t, err)
			session := iam.SessionRef{SessionID: claims.SessionID}
			hex := strings.ReplaceAll(id, "-", "")
			moved := strings.Join([]string{hex[:4], hex[4:8], hex[8:12], hex[12:16], hex[16:20], hex[20:24], hex[24:28], hex[28:]}, "-")
			for _, form := range []string{hex, "{" + id + "}", moved} {
				odd := claims
				odd.UserID, odd.Subject = form, form
				if err := f.auth.CheckSession(t.Context(), odd); !errors.Is(err, iam.ErrSessionRevoked) {
					t.Fatalf("%s kept a live session: %v", form, err)
				}
				for _, who := range []auth.Identity{
					iam.InSession(iam.UserIdentity(form), session),
					iam.InTenant(iam.UserIdentity(form), f.tenant),
				} {
					if ok, err := f.auth.Can(t.Context(), who, iam.GroupByID(g.ID), f.read); err != nil || ok {
						t.Fatalf("%s kept Can %v: %v", form, ok, err)
					}
				}
			}
			noError(t, f.auth.CheckSession(t.Context(), claims))
			if ok, err := f.auth.Can(t.Context(), iam.InSession(iam.UserIdentity(id), session), iam.GroupByID(g.ID), f.read); err != nil || !ok {
				t.Fatalf("the hyphenated id lost Can %v: %v", ok, err)
			}
		})
		other := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: other, Slug: "member-other"}))
		// Accounts never change tenant, so only claims naming another tenant
		// reach this refusal.
		t.Run("claims_naming_another_tenant", func(t *testing.T) {
			_, token, _ := signedIn(t)
			claims, err := f.auth.Verify(t.Context(), token)
			noError(t, err)
			noError(t, f.auth.CheckSession(t.Context(), claims))
			for _, tenant := range []string{other.String(), "not-a-tenant"} {
				claims.TenantID = tenant
				if err := f.auth.CheckSession(t.Context(), claims); !errors.Is(err, iam.ErrSessionRevoked) {
					t.Fatalf("claims for tenant %q kept a live session: %v", tenant, err)
				}
			}
		})
		t.Run("another_tenant_member_is_not_this_tenant", func(t *testing.T) {
			view, err := f.auth.ForTenant(t.Context(), other)
			noError(t, err)
			server := httptest.NewServer(view.Handler())
			t.Cleanup(server.Close)
			outsider := &fixture{auth: view, server: server}
			u := outsider.user(t)
			token := outsider.signIn(t, u).AccessToken
			actor, err := member(t.Context(), token)
			noError(t, err)
			if actor != (iam.TenantActor{AccountID: u.ID, TenantID: other}) {
				t.Fatalf("another tenant's member resolved as %+v", actor)
			}
			verified, err := verify.AuthenticateSession(t.Context(), f.auth, request(t.Context(), token))
			noError(t, err)
			if ok, err := f.auth.Can(t.Context(), verified.Identity(), iam.GroupByID(g.ID), f.read); err != nil || ok {
				t.Fatalf("another tenant's member gained Can %v: %v", ok, err)
			}
		})
	})
	t.Run("AK-J05-C05_late_refresh_cannot_undo_logout", func(t *testing.T) {
		u := f.user(t)
		session := f.signIn(t, u)
		if session.RefreshToken == nil {
			t.Fatal("missing refresh token")
		}
		f.call(t, "DELETE", "/logout", session.AccessToken, nil).want(t, http.StatusNoContent, "")
		f.call(t, "POST", "/token", "", map[string]string{"grant_type": "refresh_token", "refresh_token": *session.RefreshToken}).want(t, http.StatusUnauthorized, "invalid_token")
		f.call(t, "DELETE", "/logout", session.AccessToken, nil).want(t, http.StatusNoContent, "")
		f.call(t, "PATCH", "/me", session.AccessToken, map[string]string{"username": "latewriter"}).want(t, http.StatusUnauthorized, "session_revoked")
		fresh := f.signIn(t, u)
		oldClaims, err := f.auth.Verify(t.Context(), session.AccessToken)
		noError(t, err)
		newClaims, err := f.auth.Verify(t.Context(), fresh.AccessToken)
		noError(t, err)
		if oldClaims.SessionID == newClaims.SessionID {
			t.Fatal("fresh sign-in revived a retired session")
		}
	})
}
