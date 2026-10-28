package authkit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	riverhelpers "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// AccountEventsQueue is the host River queue that reads and retries account events.
const AccountEventsQueue = "authkit_account_events"

// AccountEventAttempts is how often a failed event is retried before River discards (parks) it.
const AccountEventAttempts = 10

// AccountEventConsumer applies a tenant's retained account events to the host.
// Schema holds the host's auth_event_cursors(stream text primary key, cursor text, updated_at timestamptz).
// Handle must be idempotent and act on current state: a failed event is retried after later ones.
type AccountEventConsumer struct {
	Schema    string
	Handle    func(context.Context, iam.Event) error
	Reconcile func(context.Context) error // before reading the tenant stream from an empty cursor
	Interval  time.Duration               // zero is thirty seconds
}

type accountEventsArgs struct {
	Schema string `json:"schema"`
	Tenant string `json:"tenant"`
}

func (accountEventsArgs) Kind() string { return "authkit_account_events" }

type accountEventArgs struct {
	Schema string    `json:"schema"`
	Tenant string    `json:"tenant"`
	Event  iam.Event `json:"event"`
}

func (accountEventArgs) Kind() string { return "authkit_account_event" }

type accountEventConsumer struct {
	AccountEventConsumer
	source *Client
	tenant string
	pool   *pgxpool.Pool
	fleet  *river.Client[pgx.Tx]
}

// AccountEventJobs reads this tenant's and the authority's account events on the host's River fleet.
// One unique reader runs at a time; a failed event is retried as its own job and later events go on.
func (a *Client) AccountEventJobs(c AccountEventConsumer) riverhelpers.Contribution {
	consumer := &accountEventConsumer{AccountEventConsumer: c, source: a}
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
			cfg.Queues[AccountEventsQueue] = river.QueueConfig{MaxWorkers: 2}
		}
		if err := river.AddWorkerSafely(cfg.Workers, &accountEventsWorker{c: consumer}); err != nil {
			return err
		}
		if err := river.AddWorkerSafely(cfg.Workers, &accountEventWorker{c: consumer}); err != nil {
			return err
		}
		every := c.Interval
		if every <= 0 {
			every = 30 * time.Second
		}
		args := accountEventsArgs{Schema: c.Schema, Tenant: consumer.tenant}
		cfg.PeriodicJobs = append(cfg.PeriodicJobs, riverhelpers.NewPeriodicJob(cfg, every,
			func() (river.JobArgs, *river.InsertOpts) {
				return args, &river.InsertOpts{Queue: AccountEventsQueue, UniqueOpts: river.UniqueOpts{ByArgs: true,
					ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning, rivertype.JobStateRetryable, rivertype.JobStateScheduled}}}
			}, &river.PeriodicJobOpts{ID: "authkit_account_events_" + c.Schema, RunOnStart: true}))
		return nil
	}, func(_ context.Context, b riverhelpers.Binding) error {
		consumer.pool, consumer.fleet = b.Pool, b.Client
		return nil
	}, func() error { return nil })
}

func (c *accountEventConsumer) handle(ctx context.Context, event iam.Event) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("account event handler panic: %v", p)
		}
	}()
	return c.Handle(ctx, event)
}

type accountEventsWorker struct {
	river.WorkerDefaults[accountEventsArgs]
	c *accountEventConsumer
}

// Timeout matches AuthKit's deletion budget: one handler may anonymize several tables.
func (*accountEventsWorker) Timeout(*river.Job[accountEventsArgs]) time.Duration {
	return 5 * time.Minute
}

func (*accountEventsWorker) NextRetry(*river.Job[accountEventsArgs]) time.Time {
	return time.Now().Add(30 * time.Second)
}

func (w *accountEventsWorker) Work(ctx context.Context, _ *river.Job[accountEventsArgs]) error {
	for _, authority := range []bool{false, true} {
		if err := w.c.read(ctx, authority); err != nil {
			return err
		}
	}
	return nil
}

func (c *accountEventConsumer) read(ctx context.Context, authority bool) error {
	stream := "tenant:" + c.tenant
	if authority {
		stream = "authority"
	}
	table := pgx.Identifier{c.Schema, "auth_event_cursors"}.Sanitize()
	var after string
	if err := c.pool.QueryRow(ctx, "SELECT cursor FROM "+table+" WHERE stream=$1", stream).Scan(&after); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	for batch := 0; batch < 10; batch++ {
		// Replay cannot recover expired history, so the host reconciles current state first.
		if after == "" && !authority && c.Reconcile != nil {
			if err := c.Reconcile(ctx); err != nil {
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
		var failed []river.InsertManyParams
		for _, event := range page.Events {
			err := c.handle(ctx, event)
			if err == nil {
				continue
			}
			if ctx.Err() != nil {
				return err
			}
			slog.Warn("authkit: account event failed; retrying it as its own job", "event_id", event.ID, "kind", string(event.Kind), "user_id", event.UserID, "error", err)
			failed = append(failed, river.InsertManyParams{Args: accountEventArgs{Schema: c.Schema, Tenant: c.tenant, Event: event},
				InsertOpts: &river.InsertOpts{Queue: AccountEventsQueue, MaxAttempts: AccountEventAttempts,
					ScheduledAt: time.Now().Add(accountEventDelay(0)), UniqueOpts: river.UniqueOpts{ByArgs: true}}})
		}
		if page.NextCursor != after {
			if err := advance(ctx, c.pool, c.fleet, table, stream, after, page.NextCursor, failed); err != nil {
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

// advance moves the cursor only from the position this pass read, with the page's retry jobs.
func advance(ctx context.Context, pool *pgxpool.Pool, fleet *river.Client[pgx.Tx], table, stream, previous, next string, failed []river.InsertManyParams) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	tag, err := tx.Exec(ctx, "INSERT INTO "+table+" AS current (stream, cursor) VALUES ($1, $3) ON CONFLICT (stream) DO UPDATE SET cursor=EXCLUDED.cursor, updated_at=clock_timestamp() WHERE current.cursor=$2", stream, previous, next)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("auth events: cursor for %s moved during the pass", stream)
	}
	if len(failed) > 0 {
		if _, err := fleet.InsertManyTx(ctx, tx, failed); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func accountEventDelay(retried int) time.Duration {
	switch retried {
	case 0:
		return time.Minute
	case 1:
		return 5 * time.Minute
	case 2:
		return 15 * time.Minute
	}
	return time.Hour
}

type accountEventWorker struct {
	river.WorkerDefaults[accountEventArgs]
	c *accountEventConsumer
}

func (*accountEventWorker) Timeout(*river.Job[accountEventArgs]) time.Duration {
	return 5 * time.Minute
}

func (*accountEventWorker) NextRetry(job *river.Job[accountEventArgs]) time.Time {
	return time.Now().Add(accountEventDelay(job.Attempt))
}

func (w *accountEventWorker) Work(ctx context.Context, job *river.Job[accountEventArgs]) error {
	return w.c.handle(ctx, job.Args.Event)
}
