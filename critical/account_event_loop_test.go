package critical_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
)

// accountHost is the host side of StartAccountEvents: what it applied and how many calls ran at once.
type accountHost struct {
	mu            sync.Mutex
	handled       []string
	synced        []string
	fail          map[string]bool                     // user IDs whose events and syncs fail
	after         func(context.Context, string) error // runs after a successful sync
	slow          time.Duration
	running, most int
}

func (h *accountHost) handle(_ context.Context, e iam.Event) error {
	h.mu.Lock()
	h.running++
	h.most = max(h.most, h.running)
	h.mu.Unlock()
	time.Sleep(h.slow)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.running--
	if h.fail[e.UserID] {
		return fmt.Errorf("host refused %s", e.ID)
	}
	h.handled = append(h.handled, e.ID)
	return nil
}

func (h *accountHost) sync(ctx context.Context, userID string) error {
	h.mu.Lock()
	if h.fail[userID] {
		h.mu.Unlock()
		return fmt.Errorf("host refused %s", userID)
	}
	h.synced = append(h.synced, userID)
	after := h.after
	h.mu.Unlock()
	if after != nil {
		return after(ctx, userID)
	}
	return nil
}

func (h *accountHost) seen() (handled, synced []string, most int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.handled), slices.Clone(h.synced), h.most
}

// createAccountEventTables creates the host tables exactly as Doujins migrated them.
func (f *fixture) createAccountEventTables(t *testing.T) {
	t.Helper()
	_, err := f.pool.Exec(t.Context(), strings.ReplaceAll(`
		CREATE TABLE schema.auth_event_cursors (stream text PRIMARY KEY, cursor text NOT NULL, updated_at timestamptz NOT NULL DEFAULT clock_timestamp());
		CREATE TABLE schema.account_resyncs (user_id uuid PRIMARY KEY, due_at timestamptz NOT NULL, attempts integer NOT NULL DEFAULT 0,
			last_error text, updated_at timestamptz NOT NULL DEFAULT clock_timestamp());
		CREATE INDEX account_resyncs_due_at_idx ON schema.account_resyncs (due_at)`, "schema", pgx.Identifier{f.schema}.Sanitize()))
	noError(t, err)
}

func (f *fixture) accountEventOptions(pool *pgxpool.Pool, h *accountHost, reconcile ...iam.UserStatus) authkit.AccountEventOptions {
	return authkit.AccountEventOptions{Interval: 20 * time.Millisecond, Pool: pool, Schema: f.schema, Handle: h.handle, Sync: h.sync, Reconcile: reconcile}
}

func (f *fixture) startAccountEvents(t *testing.T, pool *pgxpool.Pool, h *accountHost) *authkit.AccountEventLoop {
	t.Helper()
	view, err := f.auth.ForTenant(t.Context(), f.tenant)
	noError(t, err)
	loop, err := view.StartAccountEvents(context.Background(), f.accountEventOptions(pool, h, iam.UserStatusDeleted, iam.UserStatusBanned))
	noError(t, err)
	t.Cleanup(func() { noError(t, loop.Stop(context.Background())) })
	return loop
}

func (f *fixture) accountCursor(t *testing.T, stream string) string {
	t.Helper()
	var cursor string
	err := f.pool.QueryRow(t.Context(), "SELECT coalesce(max(cursor), '') FROM "+pgx.Identifier{f.schema, "auth_event_cursors"}.Sanitize()+" WHERE stream=$1", stream).Scan(&cursor)
	noError(t, err)
	return cursor
}

// resync reads one account_resyncs row: attempts and seconds until due, by database time.
func (f *fixture) resync(t *testing.T, userID string) (attempts int, dueIn float64, ok bool) {
	t.Helper()
	err := f.pool.QueryRow(t.Context(), "SELECT attempts, extract(epoch FROM due_at-now())::float8 FROM "+pgx.Identifier{f.schema, "account_resyncs"}.Sanitize()+" WHERE user_id=$1", userID).Scan(&attempts, &dueIn)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, false
	}
	noError(t, err)
	return attempts, dueIn, true
}

// makeDue ages only the owned resync row's due time, as its schedule would.
func (f *fixture) makeDue(t *testing.T, userID string) {
	t.Helper()
	_, err := f.pool.Exec(t.Context(), "UPDATE "+pgx.Identifier{f.schema, "account_resyncs"}.Sanitize()+" SET due_at=now() WHERE user_id=$1", userID)
	noError(t, err)
}

// drain lists a stream from after to its end.
func (f *fixture) drain(t *testing.T, after string, authority bool) ([]iam.Event, string) {
	t.Helper()
	var events []iam.Event
	for {
		page, err := f.auth.ListEvents(t.Context(), iam.EventQuery{After: after, Limit: 100, Authority: authority})
		noError(t, err)
		events = append(events, page.Events...)
		after = page.NextCursor
		if !page.HasMore {
			return events, after
		}
	}
}

func eventIDs(events []iam.Event) []string {
	ids := []string{}
	for _, e := range events {
		ids = append(ids, e.ID)
	}
	return ids
}

func TestCriticalAccountEventLoop(t *testing.T) {
	tenantStream := func(f *fixture) string { return "tenant:" + f.tenant.String() }

	t.Run("AK-J39-C01_first_use_reconciles_then_a_failing_account_is_parked_and_retried", func(t *testing.T) {
		f := newFixture(t)
		f.createAccountEventTables(t)
		gone, barred := f.user(t), f.user(t)
		rows, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{gone.ID})
		goodBatch(t, rows, err)
		noError(t, f.auth.Ban(t.Context(), iam.SystemIdentity(), barred.ID, iam.Ban{}))
		bad, good := f.user(t), f.user(t)
		h := &accountHost{fail: map[string]bool{bad.ID: true}}
		// Syncing live accounts on first use would never finish inside one pass.
		view, err := f.auth.ForTenant(t.Context(), f.tenant)
		noError(t, err)
		for _, statuses := range [][]iam.UserStatus{nil, {iam.UserStatusLive}, {iam.UserStatusActive}, {iam.UserStatusAny}, {iam.UserStatusDeleted, iam.UserStatusActive}} {
			if _, err := view.StartAccountEvents(t.Context(), f.accountEventOptions(f.pool, h, statuses...)); err == nil || !strings.Contains(err.Error(), "only deleted and banned") {
				t.Fatalf("Reconcile %q started: %v", statuses, err)
			}
		}
		loop := f.startAccountEvents(t, f.pool, h)
		events, end := f.drain(t, "", false)
		eventually(t, "tenant cursor past the failing account", func() bool { return f.accountCursor(t, tenantStream(f)) == end })
		handled, synced, _ := h.seen()
		if !slices.Equal(synced, []string{gone.ID, barred.ID}) {
			t.Fatalf("an empty cursor synced %v, want the deleted then the banned account", synced)
		}
		failed := 0
		for _, e := range events {
			if applied := slices.Contains(handled, e.ID); applied == (e.UserID == bad.ID) {
				t.Fatalf("event %s for %s applied=%v; only the failing account's events must be skipped", e.ID, e.UserID, applied)
			}
			if e.UserID == bad.ID {
				failed++
			}
		}
		if failed == 0 || !slices.ContainsFunc(events, func(e iam.Event) bool { return e.UserID == good.ID }) {
			t.Fatalf("want events for both accounts, got %d failing of %d", failed, len(events))
		}
		eventually(t, "probe healthy with a fresh parked account", func() bool { return loop.Probe(t.Context()) == nil })
		// Each failure counts one attempt. Retries follow Doujins' schedule: 1, 5 and 15 minutes, then hourly.
		wait := 60.0
		for attempts := failed; attempts <= failed+3; attempts++ {
			var dueIn float64
			eventually(t, fmt.Sprintf("parked attempt %d", attempts), func() bool { got, due, _ := f.resync(t, bad.ID); dueIn = due; return got == attempts })
			if dueIn < wait-10 || dueIn > wait {
				t.Fatalf("attempt %d is due again in %.0fs, want %.0fs", attempts, dueIn, wait)
			}
			wait = map[int]float64{1: 300, 2: 900}[attempts]
			if wait == 0 {
				wait = 3600
			}
			f.makeDue(t, bad.ID)
		}
		eventually(t, "probe reports the repeatedly failing account", func() bool {
			err := loop.Probe(t.Context())
			return err != nil && strings.Contains(err.Error(), bad.ID)
		})
		later := f.user(t)
		laterEvents, laterEnd := f.drain(t, end, false)
		eventually(t, "a new account applied while one is parked", func() bool {
			handled, _, _ := h.seen()
			return f.accountCursor(t, tenantStream(f)) == laterEnd && len(laterEvents) > 0 && slices.Contains(handled, laterEvents[len(laterEvents)-1].ID)
		})
		h.mu.Lock()
		delete(h.fail, bad.ID)
		h.mu.Unlock()
		f.makeDue(t, bad.ID)
		eventually(t, "recovered account synced and unparked", func() bool {
			_, synced, _ := h.seen()
			_, _, parked := f.resync(t, bad.ID)
			return slices.Contains(synced, bad.ID) && !parked
		})
		eventually(t, "probe healthy after recovery", func() bool { return loop.Probe(t.Context()) == nil })

		// A scheduled check (a temporary ban ending) keeps the earliest time and runs Sync when due.
		noError(t, authkit.ScheduleAccountResync(t.Context(), f.pool, f.schema, later.ID, time.Now().Add(time.Hour)))
		noError(t, authkit.ScheduleAccountResync(t.Context(), f.pool, f.schema, later.ID, time.Now().Add(2*time.Hour)))
		if attempts, dueIn, ok := f.resync(t, later.ID); !ok || attempts != 0 || dueIn < 3500 || dueIn > 3610 {
			t.Fatalf("scheduled check attempts=%d due in %.0fs (%v); want the earlier hour", attempts, dueIn, ok)
		}
		// Sync finds the ban still running and schedules the next check while the due row is handled.
		h.mu.Lock()
		h.after = func(ctx context.Context, userID string) error {
			if userID != later.ID {
				return nil
			}
			return authkit.ScheduleAccountResync(ctx, f.pool, f.schema, userID, time.Now().Add(time.Hour))
		}
		h.mu.Unlock()
		noError(t, authkit.ScheduleAccountResync(t.Context(), f.pool, f.schema, later.ID, time.Now().Add(-2*time.Second)))
		noError(t, authkit.ScheduleAccountResync(t.Context(), f.pool, f.schema, good.ID, time.Now().Add(-time.Second)))
		// Due checks run in due order, so good's settles after later's.
		eventually(t, "both due checks synced and good's removed", func() bool {
			_, synced, _ := h.seen()
			_, _, pending := f.resync(t, good.ID)
			return slices.Contains(synced, later.ID) && slices.Contains(synced, good.ID) && !pending
		})
		if attempts, dueIn, ok := f.resync(t, later.ID); !ok || attempts != 0 || dueIn < 3500 || dueIn > 3610 {
			t.Fatalf("check rescheduled during Sync: present=%v attempts=%d due in %.0fs; want it kept for the next hour", ok, attempts, dueIn)
		}
	})

	t.Run("AK-J39-C02_existing_doujins_cursor_rows_are_resumed_exactly", func(t *testing.T) {
		f := newFixture(t)
		f.createAccountEventTables(t)
		f.user(t)
		f.user(t)
		_, mid := f.drain(t, "", false)
		_, authorityEnd := f.drain(t, "", true)
		gone := f.user(t)
		rows, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{gone.ID})
		goodBatch(t, rows, err)
		f.user(t)
		// The rows the Doujins loop wrote, with its own statement.
		for stream, cursor := range map[string]string{tenantStream(f): mid, "authority": authorityEnd} {
			_, err := f.pool.Exec(t.Context(), "INSERT INTO "+pgx.Identifier{f.schema, "auth_event_cursors"}.Sanitize()+" (stream,cursor) VALUES($1,$2) ON CONFLICT(stream) DO UPDATE SET cursor=EXCLUDED.cursor,updated_at=clock_timestamp()", stream, cursor)
			noError(t, err)
		}
		tenantAfter, end := f.drain(t, mid, false)
		authorityAfter, authorityNow := f.drain(t, authorityEnd, true)
		h := &accountHost{}
		f.startAccountEvents(t, f.pool, h)
		eventually(t, "both cursors at the end of their streams", func() bool {
			return f.accountCursor(t, tenantStream(f)) == end && f.accountCursor(t, "authority") == authorityNow
		})
		handled, synced, _ := h.seen()
		if want := append(eventIDs(tenantAfter), eventIDs(authorityAfter)...); len(tenantAfter) == 0 || !slices.Equal(handled, want) {
			t.Fatalf("applied %v, want only the events after the saved cursors %v", handled, want)
		}
		if len(synced) != 0 {
			t.Fatalf("a saved cursor must not reconcile; synced %v", synced)
		}
	})

	t.Run("AK-J39-C03_one_process_reads_at_a_time_under_the_doujins_lock_key", func(t *testing.T) {
		f := newFixture(t)
		f.createAccountEventTables(t)
		f.user(t)
		// During a rolling deploy an old Doujins pod holds this exact key.
		key := f.schema + ":auth-events:" + f.tenant.String()
		old, err := pgx.ConnectConfig(t.Context(), f.pool.Config().ConnConfig)
		noError(t, err)
		t.Cleanup(func() { _ = old.Close(context.Background()) })
		_, err = old.Exec(t.Context(), "SELECT pg_advisory_lock(hashtextextended($1,0))", key)
		noError(t, err)
		h := &accountHost{slow: 20 * time.Millisecond}
		first := f.startAccountEvents(t, f.pool, h)
		other, err := pgxpool.New(t.Context(), f.pool.Config().ConnString())
		noError(t, err)
		t.Cleanup(other.Close)
		second := f.startAccountEvents(t, other, h)
		eventually(t, "both loops finished a pass", func() bool { return first.Probe(t.Context()) == nil && second.Probe(t.Context()) == nil })
		if handled, _, _ := h.seen(); len(handled) != 0 || f.accountCursor(t, tenantStream(f)) != "" {
			t.Fatalf("a loop read while the old pod held %q: applied %v", key, handled)
		}
		noError(t, old.Close(t.Context()))
		for range 6 {
			f.user(t)
			time.Sleep(30 * time.Millisecond)
		}
		events, end := f.drain(t, "", false)
		eventually(t, "tenant cursor at the end", func() bool { return f.accountCursor(t, tenantStream(f)) == end })
		handled, _, most := h.seen()
		for _, e := range events {
			if n := len(slices.DeleteFunc(slices.Clone(handled), func(id string) bool { return id != e.ID })); n != 1 {
				t.Fatalf("event %s applied %d times across two processes", e.ID, n)
			}
		}
		if most != 1 {
			t.Fatalf("%d handlers ran at once", most)
		}
	})
}
