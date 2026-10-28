package critical_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	riverkit "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// consumerLog is the host side of AccountEventJobs: what it applied, where, how often and how many at once.
type consumerLog struct {
	mu       sync.Mutex
	seen     []string
	calls    []string
	by       map[string][]string
	attempts map[string]int
	fail     map[string]int           // remaining failures per event ID; negative fails forever
	hang     map[string]bool          // waits for its context
	ignore   map[string]time.Duration // sleeps once, ignoring its context
	gate     map[string]chan struct{}
	entered  chan string
	slow     time.Duration
	running  int
	most     int
}

func newConsumerLog() *consumerLog {
	return &consumerLog{by: map[string][]string{}, attempts: map[string]int{}, fail: map[string]int{}, hang: map[string]bool{}, ignore: map[string]time.Duration{},
		gate: map[string]chan struct{}{}, entered: make(chan string, 16)}
}

func (l *consumerLog) handler(fleet string) func(context.Context, iam.Event) error {
	return func(ctx context.Context, e iam.Event) error {
		l.mu.Lock()
		l.running++
		l.most = max(l.most, l.running)
		l.attempts[e.ID]++
		l.calls = append(l.calls, e.ID)
		gate, hang, ignore := l.gate[e.ID], l.hang[e.ID], l.ignore[e.ID]
		delete(l.gate, e.ID)
		delete(l.ignore, e.ID)
		l.mu.Unlock()
		time.Sleep(ignore)
		defer func() { l.mu.Lock(); l.running--; l.mu.Unlock() }()
		if gate != nil {
			l.entered <- e.ID
			<-gate
		}
		if hang {
			<-ctx.Done()
			return ctx.Err()
		}
		time.Sleep(l.slow)
		l.mu.Lock()
		defer l.mu.Unlock()
		if n := l.fail[e.ID]; n != 0 {
			if n > 0 {
				l.fail[e.ID] = n - 1
			}
			return fmt.Errorf("host refused %s", e.ID)
		}
		l.seen = append(l.seen, e.ID)
		l.by[e.ID] = append(l.by[e.ID], fleet)
		return nil
	}
}

func (l *consumerLog) reconcile(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, "reconcile")
	return nil
}

func (l *consumerLog) snapshot() ([]string, map[string]int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	counts := map[string]int{}
	for id, fleets := range l.by {
		counts[id] = len(fleets)
	}
	return slices.Clone(l.seen), counts
}

// logSink captures AuthKit's slog records for one scenario.
type logSink struct {
	mu      sync.Mutex
	records []string
}

func (s *logSink) Enabled(context.Context, slog.Level) bool { return true }
func (s *logSink) WithAttrs([]slog.Attr) slog.Handler       { return s }
func (s *logSink) WithGroup(string) slog.Handler            { return s }
func (s *logSink) Handle(_ context.Context, r slog.Record) error {
	line := r.Level.String() + " " + r.Message
	r.Attrs(func(a slog.Attr) bool { line += " " + a.String(); return true })
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, line)
	return nil
}

func (s *logSink) has(level slog.Level, parts ...string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, line := range s.records {
		if !strings.HasPrefix(line, level.String()+" ") {
			continue
		}
		if !slices.ContainsFunc(parts, func(p string) bool { return !strings.Contains(line, p) }) {
			return true
		}
	}
	return false
}

func captureLogs(t *testing.T) *logSink {
	sink := &logSink{}
	previous := slog.Default()
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return sink
}

// createHostTables runs the host migration documented on AccountEventConsumer.
func (f *fixture) createHostTables(t *testing.T) {
	t.Helper()
	_, err := f.pool.Exec(t.Context(), "CREATE TABLE "+f.hostTable("auth_event_cursors")+
		" (stream text PRIMARY KEY, cursor text NOT NULL, updated_at timestamptz NOT NULL DEFAULT clock_timestamp());"+
		"CREATE TABLE "+f.hostTable("auth_event_parked")+" (event_id text PRIMARY KEY, event jsonb NOT NULL, attempts integer NOT NULL,"+
		" due_at timestamptz NOT NULL, last_error text NOT NULL, parked_at timestamptz NOT NULL DEFAULT clock_timestamp())")
	noError(t, err)
}

func (f *fixture) hostTable(name string) string { return pgx.Identifier{f.schema, name}.Sanitize() }

func (f *fixture) cursor(t *testing.T, stream string) string {
	t.Helper()
	var cursor string
	err := f.pool.QueryRow(t.Context(), "SELECT cursor FROM "+f.hostTable("auth_event_cursors")+" WHERE stream=$1", stream).Scan(&cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		return ""
	}
	noError(t, err)
	return cursor
}

func (f *fixture) setCursor(t *testing.T, stream, cursor string) {
	t.Helper()
	_, err := f.pool.Exec(t.Context(), "INSERT INTO "+f.hostTable("auth_event_cursors")+" (stream, cursor) VALUES ($1, $2) ON CONFLICT (stream) DO UPDATE SET cursor=EXCLUDED.cursor", stream, cursor)
	noError(t, err)
}

type parkedRow struct {
	attempts  int
	due       time.Time
	lastError string
}

func (f *fixture) parked(t *testing.T, eventID string) (parkedRow, bool) {
	t.Helper()
	var p parkedRow
	err := f.pool.QueryRow(t.Context(), "SELECT attempts, due_at, last_error FROM "+f.hostTable("auth_event_parked")+" WHERE event_id=$1", eventID).Scan(&p.attempts, &p.due, &p.lastError)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, false
	}
	noError(t, err)
	return p, true
}

// makeDue ages only the owned parked row's due time, as the retry schedule would.
func (f *fixture) makeDue(t *testing.T, eventID string) {
	t.Helper()
	_, err := f.pool.Exec(t.Context(), "UPDATE "+f.hostTable("auth_event_parked")+" SET due_at=now() WHERE event_id=$1", eventID)
	noError(t, err)
}

func (f *fixture) eventFleet(t *testing.T, log *consumerLog, name string, handleTimeout time.Duration) *river.Client[pgx.Tx] {
	t.Helper()
	view, err := f.auth.ForTenant(t.Context(), f.tenant)
	noError(t, err)
	jobs := view.AccountEventJobs(authkit.AccountEventConsumer{Schema: f.schema, Handle: log.handler(name), Reconcile: log.reconcile,
		Interval: time.Second, HandleTimeout: handleTimeout})
	fleet, err := riverkit.New(t.Context(), f.deps.Postgres, &river.Config{Schema: f.schema, FetchPollInterval: 50 * time.Millisecond, FetchCooldown: 20 * time.Millisecond}, jobs)
	noError(t, err)
	noError(t, fleet.Start(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		noError(t, fleet.Stop(ctx))
	})
	return fleet
}

func readerTicks(t *testing.T, fleet *river.Client[pgx.Tx]) int {
	t.Helper()
	page, err := fleet.JobList(t.Context(), river.NewJobListParams().Kinds("authkit_account_events").States(rivertype.JobStateCompleted).First(10000))
	noError(t, err)
	return len(page.Jobs)
}

// drain lists a stream the way the old host readers did, from after to its end.
func (f *fixture) drain(t *testing.T, after string, authority bool) ([]string, string) {
	t.Helper()
	var ids []string
	for {
		page, err := f.auth.ListEvents(t.Context(), iam.EventQuery{After: after, Limit: 100, Authority: authority})
		noError(t, err)
		for _, e := range page.Events {
			ids = append(ids, e.ID)
		}
		after = page.NextCursor
		if !page.HasMore {
			return ids, after
		}
	}
}

func (f *fixture) registered(t *testing.T, name string) iam.User {
	t.Helper()
	u, err := f.auth.CreateUser(t.Context(), iam.NewUser{Email: name + "@example.com", Username: name, EmailVerified: true})
	noError(t, err)
	return u
}

func (f *fixture) eventFor(t *testing.T, kind iam.EventKind, userID string) string {
	t.Helper()
	ids, _ := f.drain(t, "", false)
	page, err := f.auth.ListEvents(t.Context(), iam.EventQuery{Types: []string{string(kind)}, Limit: 500})
	noError(t, err)
	for _, e := range slices.Backward(page.Events) {
		if e.UserID == userID && slices.Contains(ids, e.ID) {
			return e.ID
		}
	}
	t.Fatalf("no %s event for %s", kind, userID)
	return ""
}

func TestCriticalAccountEventConsumer(t *testing.T) {
	tenantStream := func(f *fixture) string { return "tenant:" + f.tenant.String() }

	t.Run("AK-J38-C01_events_are_applied_in_log_order_after_one_reconcile", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		for _, name := range []string{"orderone", "ordertwo", "orderthree", "orderfour"} {
			f.registered(t, name)
		}
		tenantIDs, tenantCursor := f.drain(t, "", false)
		authorityIDs, authorityCursor := f.drain(t, "", true)
		log := newConsumerLog()
		f.eventFleet(t, log, "a", 5*time.Second)
		eventually(t, "both cursors at the end of their streams", func() bool {
			return f.cursor(t, tenantStream(f)) == tenantCursor && f.cursor(t, "authority") == authorityCursor
		})
		want := append(append([]string{"reconcile"}, tenantIDs...), authorityIDs...)
		if seen, _ := log.snapshot(); !slices.Equal(seen, want) {
			t.Fatalf("applied %v, want reconcile then the tenant and authority logs in order %v", seen, want)
		}
		eventually(t, "probe healthy after a pass", func() bool { return authkit.AccountEventsProbe(f.pool, f.schema)(t.Context()) == nil })
	})

	t.Run("AK-J38-C02_parked_event_is_retried_hourly_without_limit_and_reported", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		logs := captureLogs(t)
		parked := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "parkedmember").ID)
		recovers := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "recoveringmember").ID)
		later := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "latermember").ID)
		log := newConsumerLog()
		log.fail[parked], log.fail[recovers] = -1, 2
		f.eventFleet(t, log, "a", 5*time.Second)
		_, end := f.drain(t, "", false)
		eventually(t, "cursor past the failed events", func() bool { return f.cursor(t, tenantStream(f)) == end })
		if _, counts := log.snapshot(); counts[later] != 1 || counts[parked] != 0 || counts[recovers] != 0 {
			t.Fatalf("later event applied %d times, failed events %d and %d times", counts[later], counts[parked], counts[recovers])
		}
		for _, id := range []string{parked, recovers} {
			row, ok := f.parked(t, id)
			if wait := time.Until(row.due); !ok || row.attempts != 1 || wait < 50*time.Second || wait > time.Minute {
				t.Fatalf("event %s parked=%v with %d attempts, due in %s; want 1 attempt due in a minute", id, ok, row.attempts, wait)
			}
			eventually(t, "parking logged at Warn", func() bool { return logs.has(slog.LevelWarn, "account event parked", id) })
		}
		eventually(t, "probe healthy with fresh parked events", func() bool { return authkit.AccountEventsProbe(f.pool, f.schema)(t.Context()) == nil })
		schedule := map[int]time.Duration{2: 5 * time.Minute, 3: 15 * time.Minute}
		for attempts := 2; attempts <= 12; attempts++ {
			f.makeDue(t, parked)
			var row parkedRow
			eventually(t, fmt.Sprintf("parked attempt %d", attempts), func() bool { row, _ = f.parked(t, parked); return row.attempts == attempts })
			want := schedule[attempts]
			if want == 0 {
				want = time.Hour
			}
			if wait := time.Until(row.due); wait < want-10*time.Second || wait > want {
				t.Fatalf("attempt %d is due again in %s, want %s", attempts, wait, want)
			}
			eventually(t, fmt.Sprintf("failed retry %d logged at Warn", attempts), func() bool {
				return logs.has(slog.LevelWarn, "parked account event failed again", parked, fmt.Sprintf("attempts=%d", attempts))
			})
			if attempts == 3 {
				noError(t, authkit.AccountEventsProbe(f.pool, f.schema)(t.Context()))
			}
			if attempts == 4 {
				if err := authkit.AccountEventsProbe(f.pool, f.schema)(t.Context()); err == nil || !strings.Contains(err.Error(), parked) {
					t.Fatalf("probe after four failures = %v, want the parked event", err)
				}
			}
			if attempts <= 3 {
				f.makeDue(t, recovers)
			}
		}
		if _, still := f.parked(t, recovers); still {
			t.Fatal("recovered event is still parked")
		}
		log.mu.Lock()
		delete(log.fail, parked)
		log.mu.Unlock()
		f.makeDue(t, parked)
		eventually(t, "parked event finally applied", func() bool { _, ok := f.parked(t, parked); return !ok })
		noError(t, authkit.AccountEventsProbe(f.pool, f.schema)(t.Context()))
		_, counts := log.snapshot()
		if counts[parked] != 1 || counts[recovers] != 1 || counts[later] != 1 {
			t.Fatalf("applied parked %d, recovering %d and later %d times; want once each", counts[parked], counts[recovers], counts[later])
		}
	})

	t.Run("AK-J38-C03_existing_host_cursor_resumes_without_replay_or_skip", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		f.registered(t, "beforeone")
		before := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "beforetwo").ID)
		_, tenantCursor := f.drain(t, "", false)
		_, authorityCursor := f.drain(t, "", true)
		// The rows the retired host readers left behind.
		f.setCursor(t, tenantStream(f), tenantCursor)
		f.setCursor(t, "authority", authorityCursor)
		f.registered(t, "afterone")
		f.registered(t, "aftertwo")
		want, end := f.drain(t, tenantCursor, false)
		if len(want) < 2 || slices.Contains(want, before) {
			t.Fatalf("fixture listed %v after the stored cursor", want)
		}
		log := newConsumerLog()
		f.eventFleet(t, log, "a", 5*time.Second)
		eventually(t, "tenant cursor at the end", func() bool { return f.cursor(t, tenantStream(f)) == end })
		if seen, _ := log.snapshot(); !slices.Equal(seen, want) {
			t.Fatalf("resumed with %v, want exactly %v and no reconcile", seen, want)
		}
		if got := f.cursor(t, "authority"); got != authorityCursor {
			t.Fatalf("authority cursor moved from %q to %q with no new authority events", authorityCursor, got)
		}
	})

	t.Run("AK-J38-C04_two_fleets_apply_each_event_exactly_once", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		log := newConsumerLog()
		log.slow = 300 * time.Millisecond // a pass outlasts the one second period
		fleet := f.eventFleet(t, log, "a", 5*time.Second)
		f.eventFleet(t, log, "b", 5*time.Second)
		for round := range 3 {
			for i := range 3 {
				f.registered(t, fmt.Sprintf("fleetmember%d%d", round, i))
			}
			_, end := f.drain(t, "", false)
			eventually(t, fmt.Sprintf("round %d applied", round), func() bool { return f.cursor(t, tenantStream(f)) == end })
		}
		ticks := readerTicks(t, fleet)
		eventually(t, "two more ticks with nothing new", func() bool { return readerTicks(t, fleet) >= ticks+2 })
		tenantIDs, _ := f.drain(t, "", false)
		authorityIDs, _ := f.drain(t, "", true)
		seen, counts := log.snapshot()
		for _, id := range append(tenantIDs, authorityIDs...) {
			if counts[id] != 1 {
				t.Fatalf("event %s applied %d times across two fleets", id, counts[id])
			}
		}
		if len(seen) != 1+len(tenantIDs)+len(authorityIDs) {
			t.Fatalf("applied %d entries, want one reconcile and %d events", len(seen), len(tenantIDs)+len(authorityIDs))
		}
	})

	t.Run("AK-J38-C05_cursor_written_elsewhere_during_a_pass_is_kept", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		logs := captureLogs(t)
		f.registered(t, "resetbefore")
		_, start := f.drain(t, "", false)
		f.setCursor(t, tenantStream(f), start)
		f.setCursor(t, "authority", "")
		gated := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "resetgated").ID)
		f.registered(t, "resetafter")
		log := newConsumerLog()
		log.gate[gated] = make(chan struct{})
		release := log.gate[gated]
		f.eventFleet(t, log, "a", 5*time.Second)
		if got := <-log.entered; got != gated {
			t.Fatalf("entered %s first", got)
		}
		// An operator's documented reset (or the old loop's unconditional write) lands mid-pass.
		f.setCursor(t, tenantStream(f), "")
		close(release)
		_, end := f.drain(t, "", false)
		eventually(t, "reset honoured: reconcile and full replay", func() bool {
			seen, _ := log.snapshot()
			return slices.Contains(seen, "reconcile") && f.cursor(t, tenantStream(f)) == end
		})
		if !logs.has(slog.LevelError, "account event pass failed", "moved during the pass") {
			t.Fatal("the moved cursor was not logged at Error")
		}
	})

	t.Run("AK-J38-C06_one_handler_runs_at_a_time_across_fleets_and_parked_retries", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		member := f.registered(t, "concurrentmember")
		registered := f.eventFor(t, iam.EventUserRegistered, member.ID)
		log := newConsumerLog()
		log.slow = 400 * time.Millisecond // a pass outlasts the one second period
		log.fail[registered] = 1
		f.eventFleet(t, log, "a", 5*time.Second)
		f.eventFleet(t, log, "b", 5*time.Second)
		eventually(t, "registration parked", func() bool { _, ok := f.parked(t, registered); return ok })
		f.makeDue(t, registered)
		for range 2 {
			_, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{member.ID})
			noError(t, err)
			_, err = f.auth.RestoreUsers(t.Context(), iam.SystemIdentity(), []string{member.ID})
			noError(t, err)
		}
		_, end := f.drain(t, "", false)
		eventually(t, "retry and new events for the same account applied", func() bool {
			_, ok := f.parked(t, registered)
			return !ok && f.cursor(t, tenantStream(f)) == end
		})
		log.mu.Lock()
		defer log.mu.Unlock()
		if log.most != 1 {
			t.Fatalf("%d handlers ran at once, want one", log.most)
		}
	})

	t.Run("AK-J38-C07_stale_lease_is_taken_over_and_a_live_one_is_not", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		member := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "leasemember").ID)
		cursors := f.hostTable("auth_event_cursors")
		_, err := f.pool.Exec(t.Context(), "INSERT INTO "+cursors+" (stream, cursor) VALUES ('reader:lease', 'other-pod')")
		noError(t, err)
		// Another pod's heartbeat keeps its lease live; with Interval one second it goes stale after four.
		stop := make(chan struct{})
		var beat sync.WaitGroup
		beat.Go(func() {
			for {
				select {
				case <-stop:
					return
				case <-time.After(300 * time.Millisecond):
					_, _ = f.pool.Exec(context.Background(), "UPDATE "+cursors+" SET updated_at=clock_timestamp() WHERE stream='reader:lease'")
				}
			}
		})
		log := newConsumerLog()
		fleet := f.eventFleet(t, log, "a", time.Second)
		eventually(t, "three ticks while the lease is live", func() bool { return readerTicks(t, fleet) >= 3 })
		close(stop)
		beat.Wait()
		if seen, _ := log.snapshot(); len(seen) != 0 || f.cursor(t, tenantStream(f)) != "" {
			t.Fatalf("a tick ran under another pod's live lease: %v", seen)
		}
		_, err = f.pool.Exec(t.Context(), "UPDATE "+cursors+" SET updated_at=clock_timestamp() - interval '5 seconds' WHERE stream='reader:lease'")
		noError(t, err)
		eventually(t, "stale lease taken over", func() bool { _, counts := log.snapshot(); return counts[member] == 1 })
		eventually(t, "lease released", func() bool { return f.cursor(t, "reader:lease") == "" })
	})

	t.Run("AK-J38-C08_hanging_handler_parks_its_event_and_the_stream_goes_on", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		hung := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "hungmember").ID)
		later := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "afterhang").ID)
		log := newConsumerLog()
		log.hang[hung] = true
		f.eventFleet(t, log, "a", time.Second)
		_, end := f.drain(t, "", false)
		eventually(t, "stream past the hanging event", func() bool { return f.cursor(t, tenantStream(f)) == end })
		row, ok := f.parked(t, hung)
		if !ok || row.attempts != 1 || !strings.Contains(row.lastError, context.DeadlineExceeded.Error()) {
			t.Fatalf("hanging event parked=%v attempts=%d error=%q", ok, row.attempts, row.lastError)
		}
		if _, counts := log.snapshot(); counts[later] != 1 {
			t.Fatalf("event after the hang applied %d times", counts[later])
		}
	})

	t.Run("AK-J38-C09_expired_cursor_is_kept_logged_and_probed", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		logs := captureLogs(t)
		f.registered(t, "expiredmember")
		_, kept := f.drain(t, "", false)
		f.setCursor(t, tenantStream(f), kept)
		_, err := f.pool.Exec(t.Context(), "UPDATE "+f.hostTable("event_log_instance")+" SET epoch=gen_random_uuid() WHERE singleton")
		noError(t, err)
		log := newConsumerLog()
		f.eventFleet(t, log, "a", 5*time.Second)
		eventually(t, "expired history logged at Error", func() bool {
			return logs.has(slog.LevelError, "account event pass failed", "expired for "+tenantStream(f))
		})
		if got := f.cursor(t, tenantStream(f)); got != kept {
			t.Fatalf("expired cursor changed to %q", got)
		}
		if seen, _ := log.snapshot(); len(seen) != 0 {
			t.Fatalf("applied %v from an expired cursor", seen)
		}
		if err := authkit.AccountEventsProbe(f.pool, f.schema)(t.Context()); err == nil {
			t.Fatal("probe passed with an expired stream")
		}
	})

	t.Run("AK-J38-C10_holder_that_loses_its_lease_mid_pass_stops", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		logs := captureLogs(t)
		f.registered(t, "lostbefore")
		_, start := f.drain(t, "", false)
		f.setCursor(t, tenantStream(f), start)
		f.setCursor(t, "authority", "")
		gated := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "lostgated").ID)
		after := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "lostafter").ID)
		log := newConsumerLog()
		log.gate[gated] = make(chan struct{})
		release := log.gate[gated]
		f.eventFleet(t, log, "a", 5*time.Second)
		<-log.entered
		_, err := f.pool.Exec(t.Context(), "UPDATE "+f.hostTable("auth_event_cursors")+" SET cursor='other-pod', updated_at=clock_timestamp() WHERE stream='reader:lease'")
		noError(t, err)
		close(release)
		eventually(t, "lost lease logged at Error", func() bool { return logs.has(slog.LevelError, "account event pass failed", "lease lost") })
		if _, counts := log.snapshot(); counts[after] != 0 || f.cursor(t, tenantStream(f)) != start {
			t.Fatalf("the pass went on without its lease: later event applied %d times", counts[after])
		}
		eventually(t, "stale lease taken over and the stream resumed", func() bool { _, counts := log.snapshot(); return counts[after] == 1 })
	})

	t.Run("AK-J38-C11_callback_ignoring_its_context_keeps_the_lease", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		f.registered(t, "ignorebefore")
		_, start := f.drain(t, "", false)
		f.setCursor(t, tenantStream(f), start)
		f.setCursor(t, "authority", "")
		slow := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "ignoreslow").ID)
		f.registered(t, "ignoreafter")
		log := newConsumerLog()
		log.ignore[slow] = 6 * time.Second // past the one second limit and the four second lease
		f.eventFleet(t, log, "a", time.Second)
		f.eventFleet(t, log, "b", time.Second)
		_, end := f.drain(t, "", false)
		eventually(t, "stream applied after the slow callback", func() bool { return f.cursor(t, tenantStream(f)) == end })
		log.mu.Lock()
		defer log.mu.Unlock()
		if log.most != 1 || len(log.by[slow]) != 1 {
			t.Fatalf("%d handlers ran at once and the slow event was applied %d times", log.most, len(log.by[slow]))
		}
	})

	t.Run("AK-J38-C12_blocked_checkpoint_fails_the_pass_at_error", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		logs := captureLogs(t)
		_, start := f.drain(t, "", false)
		f.setCursor(t, tenantStream(f), start)
		f.setCursor(t, "authority", "")
		member := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "blockedmember").ID)
		tx, err := f.pool.Begin(t.Context())
		noError(t, err)
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		_, err = tx.Exec(t.Context(), "SELECT cursor FROM "+f.hostTable("auth_event_cursors")+" WHERE stream=$1 FOR UPDATE", tenantStream(f))
		noError(t, err)
		log := newConsumerLog()
		f.eventFleet(t, log, "a", 5*time.Second)
		eventually(t, "blocked checkpoint logged at Error", func() bool {
			return logs.has(slog.LevelError, "account event pass failed", "deadline exceeded")
		})
		noError(t, tx.Rollback(t.Context()))
		_, end := f.drain(t, "", false)
		eventually(t, "checkpoint written once the row is free", func() bool { return f.cursor(t, tenantStream(f)) == end })
		if _, counts := log.snapshot(); counts[member] < 1 {
			t.Fatal("event was never applied")
		}
	})

	t.Run("AK-J38-C13_cursor_row_deleted_during_a_pass_is_not_recreated", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		f.registered(t, "deletedbefore")
		_, start := f.drain(t, "", false)
		f.setCursor(t, tenantStream(f), start)
		f.setCursor(t, "authority", "")
		gated := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "deletedgated").ID)
		log := newConsumerLog()
		log.gate[gated] = make(chan struct{})
		release := log.gate[gated]
		f.eventFleet(t, log, "a", 5*time.Second)
		<-log.entered
		_, err := f.pool.Exec(t.Context(), "DELETE FROM "+f.hostTable("auth_event_cursors")+" WHERE stream=$1", tenantStream(f))
		noError(t, err)
		close(release)
		_, end := f.drain(t, "", false)
		eventually(t, "deleted row treated as a reset: reconcile and full replay", func() bool {
			seen, _ := log.snapshot()
			return slices.Contains(seen, "reconcile") && f.cursor(t, tenantStream(f)) == end
		})
	})

	t.Run("AK-J38-C14_parked_retries_yield_to_new_events_after_their_budget", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		log := newConsumerLog()
		var hung []string
		for i := range 5 {
			id := f.eventFor(t, iam.EventUserRegistered, f.registered(t, fmt.Sprintf("budgethung%d", i)).ID)
			hung = append(hung, id)
			log.hang[id] = true
		}
		f.eventFleet(t, log, "a", time.Second)
		eventually(t, "five hanging events parked", func() bool {
			for _, id := range hung {
				if _, ok := f.parked(t, id); !ok {
					return false
				}
			}
			return true
		})
		for _, id := range hung {
			f.makeDue(t, id)
		}
		fresh := f.eventFor(t, iam.EventUserRegistered, f.registered(t, "budgetfresh").ID)
		eventually(t, "new event applied", func() bool { _, counts := log.snapshot(); return counts[fresh] == 1 })
		log.mu.Lock()
		defer log.mu.Unlock()
		before := 0
		for _, id := range log.calls[:slices.Index(log.calls, fresh)] {
			if id == hung[4] {
				before++
			}
		}
		if before != 1 {
			t.Fatalf("the last parked event was called %d times before the new event, want only its first attempt: %v", before, log.calls)
		}
	})

	t.Run("AK-J38-C15_probe_measures_ages_in_the_database", func(t *testing.T) {
		f := newFixture(t)
		f.createHostTables(t)
		probe := authkit.AccountEventsProbe(f.pool, f.schema)
		if err := probe(t.Context()); err == nil || !strings.Contains(err.Error(), "no reader pass") {
			t.Fatalf("probe before any pass = %v", err)
		}
		cursors, parked := f.hostTable("auth_event_cursors"), f.hostTable("auth_event_parked")
		exec := func(sql string, args ...any) { _, err := f.pool.Exec(t.Context(), sql, args...); noError(t, err) }
		exec("INSERT INTO " + cursors + " (stream, cursor, updated_at) VALUES ('reader:passed', '', clock_timestamp() - interval '4 minutes 50 seconds')")
		noError(t, probe(t.Context()))
		exec("UPDATE " + cursors + " SET updated_at=clock_timestamp() - interval '5 minutes 10 seconds' WHERE stream='reader:passed'")
		if err := probe(t.Context()); err == nil || !strings.Contains(err.Error(), "no successful reader pass") {
			t.Fatalf("probe five minutes after the last pass = %v", err)
		}
		exec("UPDATE " + cursors + " SET updated_at=clock_timestamp() WHERE stream='reader:passed'")
		exec("INSERT INTO " + parked + " (event_id, event, attempts, due_at, last_error) VALUES ('overdue', '{}', 1, clock_timestamp() - interval '14 minutes 50 seconds', 'refused')")
		noError(t, probe(t.Context()))
		exec("UPDATE " + parked + " SET due_at=clock_timestamp() - interval '15 minutes 10 seconds' WHERE event_id='overdue'")
		if err := probe(t.Context()); err == nil || !strings.Contains(err.Error(), "overdue") {
			t.Fatalf("probe with a parked event fifteen minutes overdue = %v", err)
		}
	})
}
