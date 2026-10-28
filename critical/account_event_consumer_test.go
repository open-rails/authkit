package critical_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
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

// consumerLog is the host side of AccountEventJobs: what it applied, where and how often.
type consumerLog struct {
	mu       sync.Mutex
	seen     []string
	by       map[string][]string
	attempts map[string]int
	fail     map[string]int // remaining failures per event ID; negative fails forever
	slow     time.Duration
}

func newConsumerLog() *consumerLog {
	return &consumerLog{by: map[string][]string{}, attempts: map[string]int{}, fail: map[string]int{}}
}

func (l *consumerLog) handler(fleet string) func(context.Context, iam.Event) error {
	return func(_ context.Context, e iam.Event) error {
		time.Sleep(l.slow)
		l.mu.Lock()
		defer l.mu.Unlock()
		l.attempts[e.ID]++
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
	return slices.Clone(l.seen), func() map[string]int {
		out := map[string]int{}
		for id, fleets := range l.by {
			out[id] = len(fleets)
		}
		return out
	}()
}

func (f *fixture) createCursorTable(t *testing.T) {
	t.Helper()
	_, err := f.pool.Exec(t.Context(), "CREATE TABLE "+pgx.Identifier{f.schema, "auth_event_cursors"}.Sanitize()+
		" (stream text PRIMARY KEY, cursor text NOT NULL, updated_at timestamptz NOT NULL DEFAULT clock_timestamp())")
	noError(t, err)
}

func (f *fixture) cursor(t *testing.T, stream string) string {
	t.Helper()
	var cursor string
	err := f.pool.QueryRow(t.Context(), "SELECT cursor FROM "+pgx.Identifier{f.schema, "auth_event_cursors"}.Sanitize()+" WHERE stream=$1", stream).Scan(&cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		return ""
	}
	noError(t, err)
	return cursor
}

func (f *fixture) eventFleet(t *testing.T, log *consumerLog, name string) *river.Client[pgx.Tx] {
	t.Helper()
	view, err := f.auth.ForTenant(t.Context(), f.tenant)
	noError(t, err)
	jobs := view.AccountEventJobs(authkit.AccountEventConsumer{Schema: f.schema, Handle: log.handler(name), Reconcile: log.reconcile, Interval: time.Second})
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

func (f *fixture) registration(t *testing.T, u iam.User) string {
	t.Helper()
	page, err := f.auth.ListEvents(t.Context(), iam.EventQuery{Types: []string{"user.registered"}, Limit: 500})
	noError(t, err)
	for _, e := range page.Events {
		if e.UserID == u.ID {
			return e.ID
		}
	}
	t.Fatalf("no registration event for %s", u.ID)
	return ""
}

func (f *fixture) accountEventJobs(t *testing.T, fleet *river.Client[pgx.Tx]) []*rivertype.JobRow {
	t.Helper()
	page, err := fleet.JobList(t.Context(), river.NewJobListParams().Kinds("authkit_account_event").First(100))
	noError(t, err)
	return page.Jobs
}

func TestCriticalAccountEventConsumer(t *testing.T) {
	t.Run("AK-J38-C01_events_are_applied_in_log_order_after_one_reconcile", func(t *testing.T) {
		f := newFixture(t)
		f.createCursorTable(t)
		for _, name := range []string{"orderone", "ordertwo", "orderthree", "orderfour"} {
			f.registered(t, name)
		}
		tenantIDs, tenantCursor := f.drain(t, "", false)
		authorityIDs, authorityCursor := f.drain(t, "", true)
		if len(tenantIDs) < 4 {
			t.Fatalf("expected at least four tenant events, listed %d", len(tenantIDs))
		}
		log := newConsumerLog()
		f.eventFleet(t, log, "a")
		stream := "tenant:" + f.tenant.String()
		eventually(t, "both cursors at the end of their streams", func() bool {
			return f.cursor(t, stream) == tenantCursor && f.cursor(t, "authority") == authorityCursor
		})
		want := append(append([]string{"reconcile"}, tenantIDs...), authorityIDs...)
		seen, _ := log.snapshot()
		if !slices.Equal(seen, want) {
			t.Fatalf("applied %v, want reconcile then the tenant and authority logs in order %v", seen, want)
		}
	})

	t.Run("AK-J38-C02_failed_event_is_retried_then_parked_without_blocking_later_events", func(t *testing.T) {
		f := newFixture(t)
		f.createCursorTable(t)
		parked := f.registration(t, f.registered(t, "parkedmember"))
		recovers := f.registration(t, f.registered(t, "recoveringmember"))
		later := f.registration(t, f.registered(t, "latermember"))
		log := newConsumerLog()
		log.fail[parked], log.fail[recovers] = -1, 1
		fleet := f.eventFleet(t, log, "a")
		_, tenantCursor := f.drain(t, "", false)
		eventually(t, "cursor past the failed events", func() bool { return f.cursor(t, "tenant:"+f.tenant.String()) == tenantCursor })
		if _, counts := log.snapshot(); counts[later] != 1 || counts[parked] != 0 || counts[recovers] != 0 {
			t.Fatalf("later event applied %d times, failed events applied %d and %d times", counts[later], counts[parked], counts[recovers])
		}
		jobs := f.accountEventJobs(t, fleet)
		if len(jobs) != 2 {
			t.Fatalf("expected one retry job per failed event, got %d", len(jobs))
		}
		byEvent := map[string]*rivertype.JobRow{}
		for _, job := range jobs {
			var args struct {
				Event iam.Event `json:"event"`
			}
			decode(t, job.EncodedArgs, &args)
			byEvent[args.Event.ID] = job
			if job.State != rivertype.JobStateScheduled || job.MaxAttempts != authkit.AccountEventAttempts || job.Queue != authkit.AccountEventsQueue {
				t.Fatalf("retry job %d is %s with %d attempts on %s", job.ID, job.State, job.MaxAttempts, job.Queue)
			}
			if wait := time.Until(job.ScheduledAt); wait < 50*time.Second || wait > time.Minute {
				t.Fatalf("first retry is due in %s, want one minute", wait)
			}
		}
		retry := func(job *rivertype.JobRow, attempt int, done ...rivertype.JobState) *rivertype.JobRow {
			_, err := fleet.JobRetry(t.Context(), job.ID)
			noError(t, err)
			var got *rivertype.JobRow
			eventually(t, fmt.Sprintf("attempt %d of job %d", attempt, job.ID), func() bool {
				got, err = fleet.JobGet(t.Context(), job.ID)
				noError(t, err)
				return got.Attempt == attempt && slices.Contains(done, got.State)
			})
			return got
		}
		if got := retry(byEvent[recovers], 1, rivertype.JobStateCompleted); got.State != rivertype.JobStateCompleted {
			t.Fatalf("recovering event finished %s", got.State)
		}
		job := retry(byEvent[parked], 1, rivertype.JobStateRetryable)
		if wait := job.ScheduledAt.Sub(*job.AttemptedAt); wait < 5*time.Minute || wait > 5*time.Minute+5*time.Second {
			t.Fatalf("second retry is due %s after the first, want five minutes", wait)
		}
		for attempt := 2; attempt < authkit.AccountEventAttempts; attempt++ {
			job = retry(job, attempt, rivertype.JobStateRetryable)
		}
		job = retry(job, authkit.AccountEventAttempts, rivertype.JobStateDiscarded)
		if job.State != rivertype.JobStateDiscarded || len(job.Errors) != authkit.AccountEventAttempts {
			t.Fatalf("parked job is %s with %d recorded errors", job.State, len(job.Errors))
		}
		after := f.registration(t, f.registered(t, "afterparking"))
		eventually(t, "an event after parking", func() bool { _, counts := log.snapshot(); return counts[after] == 1 })
		log.mu.Lock()
		defer log.mu.Unlock()
		if log.attempts[parked] != 1+authkit.AccountEventAttempts || log.attempts[recovers] != 2 || len(log.by[recovers]) != 1 || len(log.by[parked]) != 0 {
			t.Fatalf("parked event attempted %d times, recovering event attempted %d times and applied %d times", log.attempts[parked], log.attempts[recovers], len(log.by[recovers]))
		}
	})

	t.Run("AK-J38-C03_existing_host_cursor_resumes_without_replay_or_skip", func(t *testing.T) {
		f := newFixture(t)
		f.createCursorTable(t)
		f.registered(t, "beforeone")
		before := f.registration(t, f.registered(t, "beforetwo"))
		_, tenantCursor := f.drain(t, "", false)
		_, authorityCursor := f.drain(t, "", true)
		stream := "tenant:" + f.tenant.String()
		// The rows the retired host readers left behind.
		_, err := f.pool.Exec(t.Context(), "INSERT INTO "+pgx.Identifier{f.schema, "auth_event_cursors"}.Sanitize()+" (stream, cursor) VALUES ($1, $2), ('authority', $3)", stream, tenantCursor, authorityCursor)
		noError(t, err)
		f.registered(t, "afterone")
		f.registered(t, "aftertwo")
		want, end := f.drain(t, tenantCursor, false)
		if len(want) < 2 || slices.Contains(want, before) {
			t.Fatalf("fixture listed %v after the stored cursor", want)
		}
		log := newConsumerLog()
		f.eventFleet(t, log, "a")
		eventually(t, "tenant cursor at the end", func() bool { return f.cursor(t, stream) == end })
		seen, _ := log.snapshot()
		if !slices.Equal(seen, want) {
			t.Fatalf("resumed with %v, want exactly %v and no reconcile", seen, want)
		}
		if got := f.cursor(t, "authority"); got != authorityCursor {
			t.Fatalf("authority cursor moved from %q to %q with no new authority events", authorityCursor, got)
		}
	})

	t.Run("AK-J38-C04_two_fleets_apply_each_event_exactly_once", func(t *testing.T) {
		f := newFixture(t)
		f.createCursorTable(t)
		log := newConsumerLog()
		log.slow = 400 * time.Millisecond // a pass outlasts the one second period
		fleet := f.eventFleet(t, log, "a")
		f.eventFleet(t, log, "b")
		readerRuns := func() int {
			page, err := fleet.JobList(t.Context(), river.NewJobListParams().Kinds("authkit_account_events").States(rivertype.JobStateCompleted).First(1000))
			noError(t, err)
			return len(page.Jobs)
		}
		stream := "tenant:" + f.tenant.String()
		for round := range 3 {
			for i := range 3 {
				f.registered(t, fmt.Sprintf("fleetmember%d%d", round, i))
			}
			_, end := f.drain(t, "", false)
			eventually(t, fmt.Sprintf("round %d applied", round), func() bool { return f.cursor(t, stream) == end })
		}
		runs := readerRuns()
		eventually(t, "two more reader passes with nothing new", func() bool { return readerRuns() >= runs+2 })
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
}
