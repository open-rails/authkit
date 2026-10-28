package authkit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	riverhelpers "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
)

// AccountEventsQueue is the host River queue of the account event reader's tick.
const AccountEventsQueue = "authkit_account_events"

const (
	accountEventLease  = "reader:lease"
	accountEventPassed = "reader:passed"
)

// AccountEventConsumer applies a tenant's retained account events to the host,
// one Handle at a time. Schema holds the host's tables:
//
//	auth_event_cursors(stream text PRIMARY KEY, cursor text NOT NULL, updated_at timestamptz NOT NULL DEFAULT clock_timestamp())
//	auth_event_parked(event_id text PRIMARY KEY, event jsonb NOT NULL, attempts integer NOT NULL,
//	    due_at timestamptz NOT NULL, last_error text NOT NULL, parked_at timestamptz NOT NULL DEFAULT clock_timestamp())
//
// Handle must be idempotent and act on current state: a parked event is retried after later ones.
type AccountEventConsumer struct {
	Schema        string
	Handle        func(context.Context, iam.Event) error
	Reconcile     func(context.Context) error // before reading the tenant stream from an empty cursor
	Interval      time.Duration               // zero is thirty seconds
	HandleTimeout time.Duration               // per Handle or Reconcile call; zero is AuthKit's five minute deletion budget
}

type accountEventsArgs struct {
	Schema string `json:"schema"`
	Tenant string `json:"tenant"`
}

func (accountEventsArgs) Kind() string { return "authkit_account_events" }

type accountEventConsumer struct {
	AccountEventConsumer
	source *Client
	tenant string
	pool   *pgxpool.Pool
}

// AccountEventJobs reads this tenant's and the authority's account events on the host's River fleet.
// A periodic tick takes a lease row; the holder retries due parked events, then reads new ones in order.
func (a *Client) AccountEventJobs(c AccountEventConsumer) riverhelpers.Contribution {
	consumer := &accountEventConsumer{AccountEventConsumer: c, source: a}
	if consumer.HandleTimeout <= 0 {
		consumer.HandleTimeout = 5 * time.Minute
	}
	return riverhelpers.NewContribution("authkit-account-events", func(_ context.Context, cfg *river.Config) error {
		if a == nil || c.Schema == "" || c.Handle == nil {
			return errors.New("authkit: account events need a client, host schema and handler")
		}
		tenant := a.tenantID
		if tenant.IsZero() {
			tenant = a.cfg.DefaultTenantID
		}
		if tenant.IsZero() {
			return errors.New("authkit: account events need a tenant")
		}
		consumer.tenant = tenant.String()
		if q, ok := cfg.Queues[AccountEventsQueue]; ok && q.MaxWorkers < 1 {
			return errors.New("authkit: account events queue requires workers")
		} else if !ok {
			cfg.Queues[AccountEventsQueue] = river.QueueConfig{MaxWorkers: 1}
		}
		if err := river.AddWorkerSafely(cfg.Workers, &accountEventsWorker{c: consumer}); err != nil {
			return err
		}
		every := c.Interval
		if every <= 0 {
			every = 30 * time.Second
		}
		args := accountEventsArgs{Schema: c.Schema, Tenant: consumer.tenant}
		cfg.PeriodicJobs = append(cfg.PeriodicJobs, riverhelpers.NewPeriodicJob(cfg, every,
			func() (river.JobArgs, *river.InsertOpts) {
				return args, &river.InsertOpts{Queue: AccountEventsQueue, MaxAttempts: 1}
			}, &river.PeriodicJobOpts{ID: "authkit_account_events_" + c.Schema, RunOnStart: true}))
		return nil
	}, func(_ context.Context, b riverhelpers.Binding) error {
		consumer.pool = b.Pool
		return nil
	}, func() error { return nil })
}

// AccountEventsProbe fails when no reader pass has succeeded for five minutes, or a parked
// event has failed four times or is overdue by fifteen minutes. Any host process can run it.
func AccountEventsProbe(pool *pgxpool.Pool, schema string) func(context.Context) error {
	return func(ctx context.Context) error {
		cursors := pgx.Identifier{schema, "auth_event_cursors"}.Sanitize()
		var passed time.Time
		err := pool.QueryRow(ctx, "SELECT updated_at FROM "+cursors+" WHERE stream=$1", accountEventPassed).Scan(&passed)
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("account events: no reader pass has succeeded yet")
		}
		if err != nil {
			return err
		}
		if time.Since(passed) > 5*time.Minute {
			return fmt.Errorf("account events: no successful reader pass since %s", passed.UTC().Format(time.RFC3339))
		}
		var id string
		var attempts int
		err = pool.QueryRow(ctx, "SELECT event_id, attempts FROM "+pgx.Identifier{schema, "auth_event_parked"}.Sanitize()+
			" WHERE attempts >= 4 OR due_at < now() - interval '15 minutes' ORDER BY parked_at LIMIT 1").Scan(&id, &attempts)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("account events: parked event %s failed %d times or is overdue", id, attempts)
	}
}

type accountEventsWorker struct {
	river.WorkerDefaults[accountEventsArgs]
	c *accountEventConsumer
}

// Timeout is unlimited: the lease bounds each step and a lost lease ends the pass.
func (*accountEventsWorker) Timeout(*river.Job[accountEventsArgs]) time.Duration { return -1 }

func (w *accountEventsWorker) Work(ctx context.Context, job *river.Job[accountEventsArgs]) error {
	if job.Args.Schema != w.c.Schema || job.Args.Tenant != w.c.tenant {
		err := fmt.Errorf("authkit: account events tick for %s/%s reached the reader for %s/%s", job.Args.Schema, job.Args.Tenant, w.c.Schema, w.c.tenant)
		slog.Error(err.Error())
		return river.JobCancel(err)
	}
	if err := w.c.pass(ctx); err != nil && ctx.Err() == nil {
		slog.Error("authkit: account event pass failed; cursors kept", "schema", w.c.Schema, "tenant", w.c.tenant, "error", err)
	}
	return nil
}

func (c *accountEventConsumer) table(name string) string {
	return pgx.Identifier{c.Schema, name}.Sanitize()
}

// pass runs only while it holds the lease, which expires a minute after the longest step.
func (c *accountEventConsumer) pass(ctx context.Context) error {
	token := make([]byte, 16)
	_, _ = rand.Read(token)
	lease := hex.EncodeToString(token)
	expiry := c.HandleTimeout + time.Minute
	tag, err := c.pool.Exec(ctx, "INSERT INTO "+c.table("auth_event_cursors")+" AS held (stream, cursor) VALUES ($1, $2)"+
		" ON CONFLICT (stream) DO UPDATE SET cursor=EXCLUDED.cursor, updated_at=clock_timestamp()"+
		" WHERE held.cursor='' OR held.updated_at < clock_timestamp() - make_interval(secs => $3)", accountEventLease, lease, expiry.Seconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return nil
	}
	defer func() {
		release, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_, _ = c.pool.Exec(release, "UPDATE "+c.table("auth_event_cursors")+" SET cursor='' WHERE stream=$1 AND cursor=$2", accountEventLease, lease)
	}()
	renew := func() error {
		tag, err := c.pool.Exec(ctx, "UPDATE "+c.table("auth_event_cursors")+" SET updated_at=clock_timestamp() WHERE stream=$1 AND cursor=$2", accountEventLease, lease)
		if err == nil && tag.RowsAffected() != 1 {
			err = errors.New("auth events: reader lease lost")
		}
		return err
	}
	if err := c.retryParked(ctx, renew); err != nil {
		return err
	}
	for _, authority := range []bool{false, true} {
		if err := c.read(ctx, authority, renew); err != nil {
			return err
		}
	}
	_, err = c.pool.Exec(ctx, "INSERT INTO "+c.table("auth_event_cursors")+" AS passed (stream, cursor) VALUES ($1, '')"+
		" ON CONFLICT (stream) DO UPDATE SET updated_at=clock_timestamp()", accountEventPassed)
	return err
}

func (c *accountEventConsumer) call(ctx context.Context, f func(context.Context) error) (err error) {
	step, cancel := context.WithTimeout(ctx, c.HandleTimeout)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("account event handler panic: %v", p)
		}
	}()
	return f(step)
}

func (c *accountEventConsumer) retryParked(ctx context.Context, renew func() error) error {
	parked := c.table("auth_event_parked")
	rows, err := c.pool.Query(ctx, "SELECT event, attempts FROM "+parked+" WHERE due_at <= now() ORDER BY due_at, event_id LIMIT 100")
	if err != nil {
		return err
	}
	type due struct {
		Event    iam.Event
		Attempts int
	}
	pending, err := pgx.CollectRows(rows, pgx.RowToStructByPos[due])
	if err != nil {
		return err
	}
	for _, p := range pending {
		if err := renew(); err != nil {
			return err
		}
		err := c.call(ctx, func(ctx context.Context) error { return c.Handle(ctx, p.Event) })
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			if _, err := c.pool.Exec(ctx, "DELETE FROM "+parked+" WHERE event_id=$1", p.Event.ID); err != nil {
				return err
			}
			slog.Info("authkit: parked account event applied", "event_id", p.Event.ID, "kind", string(p.Event.Kind), "user_id", p.Event.UserID, "attempts", p.Attempts+1)
			continue
		}
		next := time.Now().Add(parkedDelay(p.Attempts + 1))
		if _, err := c.pool.Exec(ctx, "UPDATE "+parked+" SET attempts=attempts+1, due_at=$2, last_error=left($3, 500) WHERE event_id=$1", p.Event.ID, next, err.Error()); err != nil {
			return err
		}
		slog.Warn("authkit: parked account event failed again", "event_id", p.Event.ID, "kind", string(p.Event.Kind), "user_id", p.Event.UserID, "attempts", p.Attempts+1, "next", next, "error", err)
	}
	return nil
}

type parkedEvent struct {
	event iam.Event
	err   error
}

func (c *accountEventConsumer) read(ctx context.Context, authority bool, renew func() error) error {
	stream := "tenant:" + c.tenant
	if authority {
		stream = "authority"
	}
	var after string
	if err := c.pool.QueryRow(ctx, "SELECT cursor FROM "+c.table("auth_event_cursors")+" WHERE stream=$1", stream).Scan(&after); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	for batch := 0; batch < 10; batch++ {
		// Replay cannot recover expired history, so the host reconciles current state first.
		if after == "" && !authority && c.Reconcile != nil {
			if err := renew(); err != nil {
				return err
			}
			if err := c.call(ctx, c.Reconcile); err != nil {
				return err
			}
		}
		page, err := c.source.ListEvents(ctx, iam.EventQuery{After: after, Limit: 100, Authority: authority})
		if errors.Is(err, iam.ErrEventCursorExpired) {
			return fmt.Errorf("auth event history expired for %s; account lifecycle recovery required: %w", stream, err)
		}
		if err != nil {
			return err
		}
		if page.NextCursor == "" {
			return errors.New("auth events: source omitted continuation cursor")
		}
		var failed []parkedEvent
		for _, event := range page.Events {
			if err := renew(); err != nil {
				return err
			}
			err := c.call(ctx, func(ctx context.Context) error { return c.Handle(ctx, event) })
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				failed = append(failed, parkedEvent{event, err})
			}
		}
		if page.NextCursor != after {
			if err := c.advance(ctx, stream, after, page.NextCursor, failed); err != nil {
				return err
			}
		}
		after = page.NextCursor
		if !page.HasMore {
			break
		}
	}
	return nil
}

// advance moves the cursor only from the position this pass read, with the page's parked events.
func (c *accountEventConsumer) advance(ctx context.Context, stream, previous, next string, failed []parkedEvent) error {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	tag, err := tx.Exec(ctx, "INSERT INTO "+c.table("auth_event_cursors")+" AS current (stream, cursor) VALUES ($1, $3)"+
		" ON CONFLICT (stream) DO UPDATE SET cursor=EXCLUDED.cursor, updated_at=clock_timestamp() WHERE current.cursor=$2", stream, previous, next)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("auth events: cursor for %s moved during the pass", stream)
	}
	due := time.Now().Add(parkedDelay(1))
	for _, f := range failed {
		data, err := json.Marshal(f.event)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO "+c.table("auth_event_parked")+" (event_id, event, attempts, due_at, last_error) VALUES ($1, $2, 1, $3, left($4, 500))"+
			" ON CONFLICT (event_id) DO NOTHING", f.event.ID, data, due, f.err.Error()); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	for _, f := range failed {
		slog.Warn("authkit: account event parked; later events go on", "event_id", f.event.ID, "kind", string(f.event.Kind), "user_id", f.event.UserID, "next", due, "error", f.err)
	}
	return nil
}

// parkedDelay is Doujins' former schedule: 1, 5 and 15 minutes, then hourly without a limit.
func parkedDelay(attempts int) time.Duration {
	switch attempts {
	case 1:
		return time.Minute
	case 2:
		return 5 * time.Minute
	case 3:
		return 15 * time.Minute
	}
	return time.Hour
}
