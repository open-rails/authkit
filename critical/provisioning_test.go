package critical_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/internal/scim"
	riverkit "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// scimTarget is a SCIM service provider at the push's external boundary, as
// the Outbox is for email: it keeps what it is sent and when, and answers 503
// to its next failing requests.
type scimTarget struct {
	mu       sync.Mutex
	users    map[string]scim.User // by the target's id
	received map[string]time.Time // by externalId: when its latest state arrived
	lists    []time.Time          // reconciliation listings
	requests []time.Time
	failing  int
	next     int
}

func newSCIMTarget() *scimTarget {
	return &scimTarget{users: map[string]scim.User{}, received: map[string]time.Time{}}
}

func (s *scimTarget) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.requests = append(s.requests, now)
	if s.failing > 0 {
		s.failing--
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", scim.MediaType)
	id, one := strings.CutPrefix(r.URL.Path, "/Users/")
	var u scim.User
	switch {
	case r.URL.Path == "/ServiceProviderConfig":
		_ = json.NewEncoder(w).Encode(scim.ServiceProviderConfig{Schemas: []string{scim.SchemaServiceProviderConfig}, Filter: scim.FilterSupport{Supported: true, MaxResults: 200}})
	case r.Method == http.MethodPost && r.URL.Path == "/Users":
		_ = json.NewDecoder(r.Body).Decode(&u)
		s.next++
		u.ID = strconv.Itoa(s.next)
		s.users[u.ID], s.received[u.ExternalID] = u, now
		w.Header().Set("Location", "/Users/"+u.ID)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(u)
	case one && r.Method == http.MethodPut:
		if _, ok := s.users[id]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&u)
		u.ID = id
		s.users[id], s.received[u.ExternalID] = u, now
		_ = json.NewEncoder(w).Encode(u)
	case one && r.Method == http.MethodDelete:
		delete(s.users, id)
		w.WriteHeader(http.StatusNoContent)
	case one && r.Method == http.MethodGet:
		if u, ok := s.users[id]; ok {
			_ = json.NewEncoder(w).Encode(u)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	case r.Method == http.MethodGet && r.URL.Path == "/Users":
		all := make([]scim.User, 0, len(s.users))
		for _, u := range s.users {
			if f := r.URL.Query().Get("filter"); f == "" || f == "externalId eq "+strconv.Quote(u.ExternalID) {
				all = append(all, u)
			}
		}
		sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		if start == 1 {
			s.lists = append(s.lists, now)
		}
		page := all[min(max(start-1, 0), len(all)):]
		_ = json.NewEncoder(w).Encode(scim.ListResponse[scim.User]{Schemas: []string{scim.SchemaListResponse}, TotalResults: len(all), StartIndex: max(start, 1), ItemsPerPage: len(page), Resources: page})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *scimTarget) fail(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failing = n
}

func (s *scimTarget) requestTimes() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.requests...)
}

func (s *scimTarget) listings() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.lists...)
}

// await is when the target received userID's latest state.
func (s *scimTarget) await(t *testing.T, userID string) time.Time {
	t.Helper()
	var at time.Time
	eventually(t, "the target receiving the account", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		at = s.received[userID]
		return !at.IsZero()
	})
	return at
}

// riverLatency bounds how late River starts a job due at an instant: its
// fetch poll and scheduler run every second and five seconds.
const riverLatency = 5 * time.Second

func withTarget(target *scimTarget, reconcile time.Duration) authtest.Option {
	return authtest.WithConfig(func(c *authkit.Config) {
		c.Provisioning = authkit.ProvisioningConfig{Targets: []authkit.ProvisioningTarget{{Name: "directory", Handler: target}}, ReconcileInterval: reconcile}
	})
}

// synced waits for the target's initial sync and empty backlog.
func (f *fixture) synced(t *testing.T) {
	t.Helper()
	eventually(t, "initial sync", func() bool {
		targets, err := f.auth.ProvisioningTargets(t.Context())
		noError(t, err)
		return len(targets) == 1 && targets[0].SyncedAt != nil && targets[0].Backlog == 0
	})
}

// ownedJobs are the jobs of kind for this fixture's schema.
func (f *fixture) ownedJobs(t *testing.T, fleet *river.Client[pgx.Tx], kind string) []*rivertype.JobRow {
	t.Helper()
	page, err := fleet.JobList(t.Context(), river.NewJobListParams().Kinds(kind).First(1000))
	noError(t, err)
	var out []*rivertype.JobRow
	for _, job := range page.Jobs {
		var args struct{ Schema string }
		decode(t, job.EncodedArgs, &args)
		if args.Schema == f.schema {
			out = append(out, job)
		}
	}
	return out
}

// outstanding are the jobs not completed.
func outstanding(jobs []*rivertype.JobRow) []*rivertype.JobRow {
	var out []*rivertype.JobRow
	for _, job := range jobs {
		if job.State != rivertype.JobStateCompleted {
			out = append(out, job)
		}
	}
	return out
}

// runCounter counts the fleet's finished runs by kind, from River's events.
type runCounter struct {
	mu   sync.Mutex
	runs map[string]int
}

func (c *runCounter) count(kind string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runs[kind]
}

// startCountedFleet is startFleet counting every run from before AuthKit's Start.
func (f *fixture) startCountedFleet(t *testing.T) (*river.Client[pgx.Tx], *runCounter) {
	t.Helper()
	fleet, err := riverkit.New(t.Context(), f.deps.Postgres, &river.Config{Schema: f.schema}, f.auth.RiverJobs())
	noError(t, err)
	events, cancel := fleet.Subscribe(river.EventKindJobCompleted, river.EventKindJobSnoozed, river.EventKindJobFailed, river.EventKindJobCancelled, river.EventKindJobInterrupted)
	counter := &runCounter{runs: map[string]int{}}
	go func() {
		for e := range events {
			counter.mu.Lock()
			counter.runs[e.Job.Kind]++
			counter.mu.Unlock()
		}
	}()
	noError(t, fleet.Start(context.Background()))
	t.Cleanup(func() {
		ctx, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		noError(t, fleet.Stop(ctx))
		cancel()
	})
	noError(t, f.auth.Start(context.Background(), authkit.WithRiverClient(fleet)))
	return fleet, counter
}

func TestCriticalProvisioningRuns(t *testing.T) {
	t.Run("AK-J41-C01_a_change_reaches_the_target_within_seconds_and_an_idle_target_runs_nothing", func(t *testing.T) {
		target := newSCIMTarget()
		f := newFixture(t, withTarget(target, 0))
		fleet, counter := f.startCountedFleet(t)
		f.synced(t)
		for range 3 {
			before := time.Now()
			u := f.user(t)
			latency := target.await(t, u.ID).Sub(before)
			if latency > riverLatency {
				t.Fatalf("change reached the target %s after its commit", latency)
			}
			t.Logf("commit to target: %s", latency.Round(time.Millisecond))
		}
		var next time.Time
		eventually(t, "one run left, for the next reconciliation", func() bool {
			left := outstanding(f.ownedJobs(t, fleet, "authkit_provisioning"))
			if len(left) != 1 || left[0].State != rivertype.JobStateScheduled {
				return false
			}
			next = left[0].ScheduledAt
			return true
		})
		targets, err := f.auth.ProvisioningTargets(t.Context())
		noError(t, err)
		if due := targets[0].ReconciledAt.Add(24 * time.Hour); next.Before(due.Add(-time.Second)) || next.After(due.Add(time.Second)) {
			t.Fatalf("idle target's next run at %s, reconciliation due %s", next, due)
		}
		before, requests := counter.count("authkit_provisioning"), len(target.requestTimes())
		time.Sleep(6 * time.Second) // past River's 5 s scheduler interval
		if after := counter.count("authkit_provisioning"); after != before || len(target.requestTimes()) != requests {
			t.Fatalf("idle target ran %d jobs", after-before)
		}
		t.Logf("%d runs for the initial sync and 3 changes; none idle; next run in %s", before, time.Until(next).Round(time.Minute))
	})
	t.Run("AK-J41-C02_an_unreachable_target_is_retried_at_its_retry_at_and_no_sooner", func(t *testing.T) {
		target := newSCIMTarget()
		f := newFixture(t, withTarget(target, 0))
		f.startFleet(t)
		f.synced(t)
		sent := len(target.requestTimes())
		target.fail(2)
		u := f.user(t)
		eventually(t, "the first failed request", func() bool { return len(target.requestTimes()) > sent })
		// A change during the backoff waits for its retry_at too.
		v := f.user(t)
		delivered := target.await(t, u.ID)
		if at := target.await(t, v.ID); at.After(delivered) {
			delivered = at
		}
		times := target.requestTimes()[sent:]
		first, second, third := times[0], times[1], times[2]
		for _, step := range []struct {
			from, to time.Time
			backoff  time.Duration
		}{{first, second, time.Second}, {second, third, 2 * time.Second}} {
			if wait := step.to.Sub(step.from); wait < step.backoff || wait > step.backoff+riverLatency {
				t.Fatalf("retry after %s, backoff %s", wait, step.backoff)
			}
		}
		t.Logf("retries at +%s and +%s; delivered %s after the first failure", second.Sub(first).Round(time.Millisecond), third.Sub(second).Round(time.Millisecond), delivered.Sub(first).Round(time.Millisecond))
		eventually(t, "the recovered target reported healthy", func() bool {
			targets, err := f.auth.ProvisioningTargets(t.Context())
			noError(t, err)
			return targets[0].FailingSince == nil && targets[0].LastError == nil
		})
	})
	t.Run("AK-J41-C03_reconciliation_runs_at_its_interval", func(t *testing.T) {
		target := newSCIMTarget()
		const interval = 2 * time.Second
		f := newFixture(t, withTarget(target, interval))
		_, counter := f.startCountedFleet(t)
		f.user(t)
		f.synced(t)
		// When each reconciliation began, as AuthKit records it.
		var began []time.Time
		watch := func(n int) {
			deadline := time.Now().Add(time.Duration(n) * (interval + riverLatency))
			for len(began) < n && time.Now().Before(deadline) {
				targets, err := f.auth.ProvisioningTargets(t.Context())
				noError(t, err)
				if at := targets[0].ReconciledAt; at != nil && (len(began) == 0 || at.After(began[len(began)-1])) {
					began = append(began, *at)
				}
				time.Sleep(20 * time.Millisecond)
			}
			if len(began) < n {
				t.Fatalf("%d reconciliations, want %d", len(began), n)
			}
		}
		watch(3)
		before, listed := counter.count("authkit_provisioning"), len(target.listings())
		watch(5)
		for i := 1; i < len(began); i++ {
			if gap := began[i].Sub(began[i-1]); gap < interval || gap > interval+riverLatency {
				t.Fatalf("reconciliation %d began %s after the last (interval %s)", i, gap, interval)
			}
		}
		listings := len(target.listings()) - listed
		if listings < 2 {
			t.Fatalf("%d listings for 2 reconciliations", listings)
		}
		if extra := counter.count("authkit_provisioning") - before - listings; extra > 1 {
			t.Fatalf("%d runs beyond the reconciliations", extra)
		}
		t.Logf("reconciliations every %v (interval %s)", gaps(began), interval)
	})
	t.Run("AK-J41-C04_a_listener_down_at_the_write_catches_up_on_reconnect", func(t *testing.T) {
		target := newSCIMTarget()
		f := newFixture(t, withTarget(target, 0))
		f.startFleet(t)
		f.synced(t)
		listening := "SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND query='LISTEN authkit_provisioning'"
		for attempt := 0; ; attempt++ {
			eventually(t, "the listener connected", func() bool {
				var pid int
				return f.pool.QueryRow(t.Context(), listening).Scan(&pid) == nil
			})
			var cut bool
			noError(t, f.pool.QueryRow(t.Context(), "SELECT bool_and(pg_terminate_backend(pid, 5000)) FROM ("+listening+") l").Scan(&cut))
			if !cut {
				t.Fatal("the listener's connection was not cut")
			}
			u := f.user(t)
			written := time.Now()
			// No listener from the cut until now, so the change's NOTIFY was lost.
			var down bool
			noError(t, f.pool.QueryRow(t.Context(), "SELECT NOT EXISTS ("+listening+")").Scan(&down))
			if !down {
				if attempt == 3 {
					t.Fatal("the listener reconnected before every write")
				}
				continue
			}
			at := target.await(t, u.ID)
			t.Logf("written with the listener down; delivered %s later, on its reconnect", at.Sub(written).Round(time.Millisecond))
			return
		}
	})
}

func gaps(times []time.Time) []time.Duration {
	out := make([]time.Duration, 0, len(times))
	for i := 1; i < len(times); i++ {
		out = append(out, times[i].Sub(times[i-1]).Round(10*time.Millisecond))
	}
	return out
}
