package critical_test

import (
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	riverkit "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

// pooled is a fixture whose Deps.Postgres goes through PgBouncer in
// transaction mode, which keeps no prepared statements
// (max_prepared_statements = 0), and whose Deps.PostgresSession reaches
// PostgreSQL directly through a link the test can stall. app names AuthKit's
// direct sessions in pg_stat_activity.
type pooled struct {
	*fixture
	bouncer *pgxpool.Pool
	session *pgxpool.Config
	link    *sessionLink
	app     string
}

// bouncerPool is a pool through PgBouncer in the pooling-safe exec mode.
func bouncerPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("AUTHKIT_TEST_PGBOUNCER_URL")
	if url == "" {
		t.Fatal("the transaction-pooler journey requires AUTHKIT_TEST_PGBOUNCER_URL; skipping is not qualification")
	}
	cfg, err := pgxpool.ParseConfig(url)
	noError(t, err)
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	noError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func newPooledFixture(t *testing.T, options ...authtest.Option) *pooled {
	t.Helper()
	p := &pooled{bouncer: bouncerPool(t), app: "authkit-direct-" + strings.ToLower(rand.Text()[:10])}
	session, err := pgxpool.ParseConfig(os.Getenv("AUTHKIT_TEST_DATABASE_URL"))
	noError(t, err)
	p.link = newSessionLink(t, net.JoinHostPort(session.ConnConfig.Host, strconv.Itoa(int(session.ConnConfig.Port))))
	session.ConnConfig.Host, session.ConnConfig.Port, session.ConnConfig.Fallbacks = "127.0.0.1", p.link.port(), nil
	session.ConnConfig.RuntimeParams["application_name"] = p.app
	p.session = session
	p.fixture = newFixture(t, append([]authtest.Option{authtest.WithDeps(func(d *authkit.Deps) {
		d.Postgres, d.PostgresSession = p.bouncer, p.session
	})}, options...)...)
	return p
}

// direct counts AuthKit's direct sessions running query, or all of them.
func (p *pooled) direct(t *testing.T, query string) int {
	t.Helper()
	var n int
	noError(t, p.pool.QueryRow(t.Context(), "SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND ($2='' OR query=$2)", p.app, query).Scan(&n))
	return n
}

// listener is the pid of the direct session listening for provisioning
// changes, other than those in old; zero while there is none.
func (p *pooled) listener(t *testing.T, old ...int) int {
	t.Helper()
	rows, err := p.pool.Query(t.Context(), "SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND query='LISTEN authkit_provisioning'", p.app)
	noError(t, err)
	pids, err := pgx.CollectRows(rows, pgx.RowTo[int])
	noError(t, err)
	for _, pid := range pids {
		if !slices.Contains(old, pid) {
			return pid
		}
	}
	return 0
}

// jobs reads the fixture's River jobs without working them.
func (p *pooled) jobs(t *testing.T) *river.Client[pgx.Tx] {
	t.Helper()
	c, err := river.NewClient(riverpgxv5.New(p.pool), &river.Config{Schema: p.schema})
	noError(t, err)
	return c
}

// idle waits until no job of kind is left to run, so the next one is
// inserted, not queued behind it.
func (p *pooled) idle(t *testing.T, jobs *river.Client[pgx.Tx], kind string) {
	t.Helper()
	eventually(t, "no "+kind+" job left", func() bool { return len(outstanding(p.ownedJobs(t, jobs, kind))) == 0 })
}

// free reports that no session holds the advisory lock lock takes.
func (p *pooled) free(t *testing.T, lock string, args ...any) bool {
	t.Helper()
	conn, err := pgx.ConnectConfig(t.Context(), p.pool.Config().ConnConfig)
	noError(t, err)
	defer conn.Close(context.Background())
	var ok bool
	noError(t, conn.QueryRow(t.Context(), "SELECT "+lock, args...).Scan(&ok))
	return ok
}

// sessionLink carries AuthKit's direct sessions to PostgreSQL. stall freezes
// the connections open at that moment without closing them, as a silent
// network partition does; later connections pass.
type sessionLink struct {
	listener net.Listener
	target   string
	closed   chan struct{}
	mu       sync.Mutex
	relays   map[*relay]struct{}
}

type relay struct {
	client, server net.Conn
	stalled        chan struct{}
}

func newSessionLink(t *testing.T, target string) *sessionLink {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	noError(t, err)
	l := &sessionLink{listener: listener, target: target, closed: make(chan struct{}), relays: map[*relay]struct{}{}}
	t.Cleanup(l.close)
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go l.relay(client)
		}
	}()
	return l
}

func (l *sessionLink) port() uint16 { return uint16(l.listener.Addr().(*net.TCPAddr).Port) }

func (l *sessionLink) relay(client net.Conn) {
	server, err := net.DialTimeout("tcp", l.target, time.Second)
	if err != nil {
		_ = client.Close()
		return
	}
	r := &relay{client: client, server: server, stalled: make(chan struct{})}
	l.mu.Lock()
	select {
	case <-l.closed:
		l.mu.Unlock()
		_ = client.Close()
		_ = server.Close()
		return
	default:
	}
	l.relays[r] = struct{}{}
	l.mu.Unlock()
	done := make(chan struct{})
	go func() { l.pipe(server, client, r.stalled); close(done) }()
	l.pipe(client, server, r.stalled)
	<-done
	_ = client.Close()
	_ = server.Close()
	l.mu.Lock()
	delete(l.relays, r)
	l.mu.Unlock()
}

// pipe copies src to dst until either fails; once stalled, it holds what it
// reads until the link closes.
func (l *sessionLink) pipe(dst, src net.Conn, stalled <-chan struct{}) {
	defer func() { _ = dst.Close(); _ = src.Close() }()
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			select {
			case <-stalled:
				<-l.closed
				return
			default:
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (l *sessionLink) stall() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for r := range l.relays {
		close(r.stalled)
	}
}

func (l *sessionLink) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.closed:
		return
	default:
	}
	close(l.closed)
	_ = l.listener.Close()
	for r := range l.relays {
		_ = r.client.Close()
		_ = r.server.Close()
	}
}

// Serial: it measures how soon River and the provisioning listener act on a
// notification, against polls of 10 and 30 seconds.
func TestCriticalTransactionPooler(t *testing.T) {
	t.Run("AK-J47-C01_through_a_transaction_pooler_keeping_no_prepared_statements_accounts_sign_in_and_jobs_run_on_notification", func(t *testing.T) {
		var purgedAt sync.Map
		p := newPooledFixture(t, authtest.WithDeps(func(d *authkit.Deps) {
			d.OnPurge = func(_ context.Context, deletion iam.UserDeletion) error {
				purgedAt.LoadOrStore(deletion.UserID, time.Now())
				return nil
			}
		}))
		// A pool that prepares named statements cannot share server connections.
		cfg, deps := p.cfg, p.deps
		named, err := pgxpool.New(t.Context(), os.Getenv("AUTHKIT_TEST_PGBOUNCER_URL"))
		noError(t, err)
		t.Cleanup(named.Close)
		deps.Postgres = named
		if _, err := authkit.New(t.Context(), cfg, deps); err == nil || !strings.Contains(err.Error(), "DefaultQueryExecMode") {
			t.Fatalf("New accepted a pool that keeps named statements behind a transaction pooler: %v", err)
		}
		users := make([]authtest.User, 8)
		for i := range users {
			users[i] = p.user(t)
		}
		// Concurrent sign-ins share PgBouncer's server connections.
		var wg sync.WaitGroup
		results := make([]response, len(users))
		failures := make([]error, len(users))
		for i, u := range users {
			wg.Go(func() {
				results[i], failures[i] = p.request(t.Context(), "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password})
			})
		}
		wg.Wait()
		for i, u := range users {
			noError(t, failures[i])
			token := tokensFrom(t, results[i], u.ID).AccessToken
			if id := p.identity(t, token); id.Subject != u.ID {
				t.Fatalf("session of %s authenticates %s", u.ID, id.Subject)
			}
			p.call(t, "GET", "/me", token, nil).want(t, http.StatusOK, "")
		}
		eventually(t, "no direct session left after boot", func() bool { return p.direct(t, "") == 0 })
		noError(t, p.auth.Start(context.Background()))
		eventually(t, "River listening on its one direct session", func() bool { return p.direct(t, "") == 1 })
		warm := users[3]
		rows, err := p.auth.PurgeUsers(t.Context(), []string{warm.ID})
		goodBatch(t, rows, err)
		p.purged(t, warm.ID)
		// AuthKit's own River polls every 10 s: a callback within 3 s of its
		// purge was woken by the insert's notification.
		jobs := p.jobs(t)
		for _, u := range users[:3] {
			p.idle(t, jobs, "authkit_account_delete_due")
			start := time.Now()
			rows, err := p.auth.PurgeUsers(t.Context(), []string{u.ID})
			goodBatch(t, rows, err)
			p.purged(t, u.ID)
			at, _ := purgedAt.Load(u.ID)
			if took := at.(time.Time).Sub(start); took > 3*time.Second {
				t.Fatalf("cleanup callback ran %s after the purge: River missed its notification", took)
			}
		}
	})

	t.Run("AK-J47-C02_provisioning_notifications_reach_a_direct_listener_and_a_cut_or_stalled_listener_catches_up", func(t *testing.T) {
		// Notification: River polls every 10 s, the listener checks every 30 s.
		target := newSCIMTarget()
		p := newPooledFixture(t, withTarget(target)...)
		noError(t, p.auth.Start(context.Background()))
		p.synced(t)
		eventually(t, "the provisioning listener on a direct session", func() bool { return p.listener(t) != 0 })
		target.await(t, p.user(t).ID)
		jobs := p.jobs(t)
		for range 3 {
			p.idle(t, jobs, "authkit_provisioning")
			before := time.Now()
			u := p.user(t)
			if latency := target.await(t, u.ID).Sub(before); latency > riverLatency {
				t.Fatalf("change reached the target %s after its commit: a notification was lost", latency)
			}
		}

		// Catch-up: a host fleet through the pooler, its listener on the
		// link too, and the provisioning listener checking every second.
		target = newSCIMTarget()
		p = newPooledFixture(t, append(withTarget(target), authtest.WithConfig(func(c *authkit.Config) {
			config.Tune(c, func(tn *config.Tuning) { tn.ListenerCheck = time.Second })
		}))...)
		fleet, err := riverkit.NewWithSession(t.Context(), p.bouncer, p.session, &river.Config{Schema: p.schema}, p.auth.RiverJobs())
		noError(t, err)
		noError(t, fleet.Start(context.Background()))
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			noError(t, fleet.Stop(ctx))
		})
		noError(t, p.auth.Start(context.Background(), authkit.WithRiverClient(fleet)))
		p.synced(t)
		for attempt := 0; ; attempt++ {
			var pid int
			eventually(t, "the listener connected", func() bool { pid = p.listener(t); return pid != 0 })
			var cut bool
			noError(t, p.pool.QueryRow(t.Context(), "SELECT pg_terminate_backend($1, 5000)", pid).Scan(&cut))
			if !cut {
				t.Fatal("the listener's connection was not cut")
			}
			u := p.user(t)
			if p.listener(t) != 0 {
				if attempt == 3 {
					t.Fatal("the listener reconnected before every write")
				}
				continue
			}
			target.await(t, u.ID)
			break
		}
		eventually(t, "no run in flight", func() bool {
			return len(outstanding(p.ownedJobs(t, fleet, "authkit_provisioning"))) == 0
		})
		var stalled int
		eventually(t, "the listener connected", func() bool { stalled = p.listener(t); return stalled != 0 })
		p.link.stall()
		u := p.user(t)
		target.await(t, u.ID)
		if p.listener(t, stalled) == 0 {
			t.Fatal("a change written while the listener stalled arrived without a new listener")
		}
	})

	t.Run("AK-J47-C03_session_locks_through_a_pooler_exclude_and_end_with_their_holder", func(t *testing.T) {
		var calls atomic.Int32
		p := newPooledFixture(t, authtest.WithDeps(func(d *authkit.Deps) {
			d.OnPurge = func(context.Context, iam.UserDeletion) error { calls.Add(1); return nil }
		}))
		noError(t, p.auth.Start(context.Background()))

		// An account's cleanup callback waits for its lock, on a direct session.
		u := p.user(t)
		key := "authkit-account-callback:" + p.schema + ":" + p.cfg.Issuer + ":" + u.ID
		holder, err := pgx.ConnectConfig(t.Context(), p.pool.Config().ConnConfig)
		noError(t, err)
		t.Cleanup(func() { _ = holder.Close(context.Background()) })
		_, err = holder.Exec(t.Context(), "SELECT pg_advisory_lock(hashtext(current_database()), hashtext($1))", key)
		noError(t, err)
		rows, err := p.auth.PurgeUsers(t.Context(), []string{u.ID})
		goodBatch(t, rows, err)
		eventually(t, "the callback waiting for its lock on a direct session", func() bool {
			var waiting bool
			noError(t, p.pool.QueryRow(t.Context(), `SELECT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_stat_activity a USING (pid)
				WHERE l.locktype='advisory' AND NOT l.granted AND l.classid=hashtext(current_database())::oid AND l.objid=hashtext($1)::oid AND l.objsubid=2 AND a.application_name=$2)`, key, p.app).Scan(&waiting))
			return waiting
		})
		if calls.Load() != 0 {
			t.Fatal("the callback ran while another holder held its lock")
		}
		noError(t, holder.Close(t.Context()))
		p.purged(t, u.ID)
		if calls.Load() != 1 {
			t.Fatalf("the callback ran %d times", calls.Load())
		}
		eventually(t, "the callback's lock released with its session", func() bool {
			return p.free(t, "pg_try_advisory_lock(hashtext(current_database()), hashtext($1))", key)
		})

		// Account-event readers on the pooled pool elect one reader.
		p.createAccountEventTables(t)
		p.user(t)
		election := p.schema + ":auth-events:" + p.tenant.String()
		old, err := pgx.ConnectConfig(t.Context(), p.pool.Config().ConnConfig)
		noError(t, err)
		t.Cleanup(func() { _ = old.Close(context.Background()) })
		_, err = old.Exec(t.Context(), "SELECT pg_advisory_lock(hashtextextended($1,0))", election)
		noError(t, err)
		view, err := p.auth.ForTenant(t.Context(), p.tenant)
		noError(t, err)
		h := &accountHost{slow: 20 * time.Millisecond}
		var loops []*authkit.AccountEventLoop
		for _, pool := range []*pgxpool.Pool{p.bouncer, bouncerPool(t)} {
			o := p.accountEventOptions(pool, h, iam.UserStatusDeleted, iam.UserStatusBanned)
			o.Session = p.session
			loop, err := view.StartAccountEvents(context.Background(), o)
			noError(t, err)
			t.Cleanup(func() { _ = loop.Stop(context.Background()) })
			loops = append(loops, loop)
		}
		eventually(t, "both readers finished a pass", func() bool {
			return loops[0].Probe(t.Context()) == nil && loops[1].Probe(t.Context()) == nil
		})
		if handled, _, _ := h.seen(); len(handled) != 0 {
			t.Fatalf("a reader read while another session held the election: applied %v", handled)
		}
		noError(t, old.Close(t.Context()))
		for range 4 {
			p.user(t)
			time.Sleep(30 * time.Millisecond)
		}
		events, end := p.drain(t, "", false)
		eventually(t, "tenant cursor at the end", func() bool { return p.accountCursor(t, "tenant:"+p.tenant.String()) == end })
		for _, loop := range loops {
			noError(t, loop.Stop(t.Context()))
		}
		handled, _, most := h.seen()
		for _, e := range events {
			if n := len(slices.DeleteFunc(slices.Clone(handled), func(id string) bool { return id != e.ID })); n != 1 {
				t.Fatalf("event %s applied %d times across two readers", e.ID, n)
			}
		}
		if most != 1 {
			t.Fatalf("%d handlers ran at once", most)
		}
		eventually(t, "the election released with its sessions", func() bool {
			return p.free(t, "pg_try_advisory_lock(hashtextextended($1,0))", election)
		})
	})
}
