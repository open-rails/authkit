package authkit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
)

// AccountEventOptions configures a host's account event loop. Schema holds the
// host's auth_event_cursors and account_resyncs tables (docs/event-log.md) for
// one tenant: the authority cursor is not per tenant.
type AccountEventOptions struct {
	Interval time.Duration // zero uses thirty seconds
	Pool     *pgxpool.Pool
	Schema   string
	Handle   func(context.Context, iam.Event) error
	// Sync applies one account's current state. It retries parked and due
	// accounts, and syncs every account in the Reconcile statuses (deleted,
	// banned or both) before first use or after an operator resets the
	// tenant cursor. A failed first-use sync is not parked: it fails the pass.
	Sync      func(ctx context.Context, userID string) error
	Reconcile []iam.UserStatus
}

// AccountEventLoop is a running StartAccountEvents loop.
type AccountEventLoop struct {
	client      *Client
	options     AccountEventOptions
	cancel      context.CancelFunc
	done        chan struct{}
	mu          sync.RWMutex
	lastError   error
	lastSuccess time.Time
}

// StartAccountEvents reads this tenant view's events and the authority events
// into the host. It runs one bounded pass immediately and then every thirty
// seconds. A dedicated advisory-lock connection elects one reader per host
// schema and tenant without occupying a pooled connection while a handler uses
// the database. A failed event parks its account for Sync and the stream moves on.
func (a *Client) StartAccountEvents(ctx context.Context, o AccountEventOptions) (*AccountEventLoop, error) {
	if a == nil || a.tenantID.IsZero() || o.Pool == nil || o.Schema == "" || o.Handle == nil || o.Sync == nil {
		return nil, errors.New("authkit: account events need a ForTenant view, Pool, Schema, Handle and Sync")
	}
	// Syncing live accounts on first use would never finish inside one pass.
	if len(o.Reconcile) == 0 || slices.ContainsFunc(o.Reconcile, func(s iam.UserStatus) bool { return s != iam.UserStatusDeleted && s != iam.UserStatusBanned }) {
		return nil, fmt.Errorf("authkit: account events reconcile only deleted and banned accounts, not %q", o.Reconcile)
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &AccountEventLoop{client: a, options: o, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		interval := o.Interval
		if interval <= 0 {
			interval = 30 * time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			// Match AuthKit's terminal-deletion worker budget. One handler may
			// synchronize and anonymize multiple replica-backed signal tables;
			// the poll cadence is not a deadline for that business operation.
			pass, finish := context.WithTimeout(ctx, 5*time.Minute)
			err := r.poll(pass)
			finish()
			r.mu.Lock()
			r.lastError = err
			if err == nil {
				r.lastSuccess = time.Now()
			}
			r.mu.Unlock()
			if err != nil && ctx.Err() == nil {
				slog.Warn("authkit: account event polling failed; cursor retained for retry", "failure", "pass_error", "schema", o.Schema, "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return r, nil
}

func (r *AccountEventLoop) Stop(ctx context.Context) error {
	r.cancel()
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Probe fails after a failed pass, after five minutes without a good pass, or
// while a parked account is 15 minutes overdue or has failed four times.
func (r *AccountEventLoop) Probe(ctx context.Context) error {
	r.mu.RLock()
	err, lastSuccess := r.lastError, r.lastSuccess
	r.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("account events pass error: %w", err)
	}
	if time.Since(lastSuccess) > 5*time.Minute {
		return errors.New("account events: no successful pass in the last 5 minutes")
	}
	var userID string
	table := pgx.Identifier{r.options.Schema, "account_resyncs"}.Sanitize()
	err = r.options.Pool.QueryRow(ctx, "SELECT user_id::text FROM "+table+" WHERE due_at < now()-interval '15 minutes' OR attempts >= 4 ORDER BY due_at LIMIT 1").Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("account events parked user %s: resync overdue by more than 15 minutes or failing repeatedly", userID)
}

// ScheduleAccountResync asks the loop to Sync an account at dueAt, for state
// that records no event, such as a temporary ban ending. A due check has just
// been satisfied; preserve any earlier future check.
func ScheduleAccountResync(ctx context.Context, pool *pgxpool.Pool, schema, userID string, dueAt time.Time) error {
	table := pgx.Identifier{schema, "account_resyncs"}.Sanitize()
	_, err := pool.Exec(ctx, `INSERT INTO `+table+` AS pending (user_id, due_at) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET
			due_at = CASE WHEN pending.due_at <= clock_timestamp() THEN EXCLUDED.due_at ELSE LEAST(pending.due_at, EXCLUDED.due_at) END,
			attempts = CASE WHEN pending.due_at <= clock_timestamp() THEN 0 ELSE pending.attempts END,
			last_error = CASE WHEN pending.due_at <= clock_timestamp() THEN NULL ELSE pending.last_error END,
			updated_at = clock_timestamp()`, userID, dueAt)
	return err
}

func (r *AccountEventLoop) park(ctx context.Context, userID, kind string, cause error, dueAt time.Time, attempts int) error {
	table := pgx.Identifier{r.options.Schema, "account_resyncs"}.Sanitize()
	// Only replace a due check's deadline if it has not been rescheduled while
	// Sync ran. New event failures always preserve the earliest pending check.
	err := r.options.Pool.QueryRow(ctx, `INSERT INTO `+table+` AS pending (user_id, due_at, attempts, last_error)
		VALUES ($1, clock_timestamp()+interval '1 minute', 1, left($2, 500))
		ON CONFLICT (user_id) DO UPDATE SET
			due_at = LEAST(
				CASE WHEN pending.due_at = $3 AND pending.attempts = $4 THEN 'infinity'::timestamptz ELSE pending.due_at END,
				clock_timestamp() + CASE pending.attempts WHEN 0 THEN interval '1 minute' WHEN 1 THEN interval '5 minutes' WHEN 2 THEN interval '15 minutes' ELSE interval '1 hour' END),
			attempts = pending.attempts + 1, last_error = EXCLUDED.last_error, updated_at = clock_timestamp()
		RETURNING attempts`, userID, cause.Error(), dueAt, attempts).Scan(&attempts)
	if err != nil {
		return fmt.Errorf("park account %s after %v: %w", userID, cause, err)
	}
	slog.Warn("authkit: account event failed; user parked for resync", "failure", "parked_user", "schema", r.options.Schema, "user_id", userID, "kind", kind, "attempts", attempts, "error", cause)
	return nil
}

func (r *AccountEventLoop) resyncDue(ctx context.Context) error {
	table := pgx.Identifier{r.options.Schema, "account_resyncs"}.Sanitize()
	rows, err := r.options.Pool.Query(ctx, "SELECT user_id::text, due_at, attempts, updated_at FROM "+table+" WHERE due_at <= now() ORDER BY due_at LIMIT 100")
	if err != nil {
		return err
	}
	type resync struct {
		UserID    string
		DueAt     time.Time
		Attempts  int
		UpdatedAt time.Time
	}
	pending, err := pgx.CollectRows(rows, pgx.RowToStructByPos[resync])
	if err != nil {
		return err
	}
	for _, row := range pending {
		if err := r.options.Sync(ctx, row.UserID); err != nil {
			if err := r.park(ctx, row.UserID, "resync", err, row.DueAt, row.Attempts); err != nil {
				return err
			}
			continue
		}
		_, err := r.options.Pool.Exec(ctx, "DELETE FROM "+table+" WHERE user_id=$1 AND due_at=$2 AND attempts=$3 AND updated_at=$4", row.UserID, row.DueAt, row.Attempts, row.UpdatedAt)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *AccountEventLoop) poll(ctx context.Context) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("auth event handler panic: %v", p)
		}
	}()
	o, tenant := r.options, r.client.tenantID.String()
	connect, finishConnect := context.WithTimeout(ctx, 30*time.Second)
	conn, err := pgx.ConnectConfig(connect, o.Pool.Config().ConnConfig)
	finishConnect()
	if err != nil {
		return err
	}
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = conn.Close(clean)
	}()
	var acquired bool
	lock, finishLock := context.WithTimeout(ctx, 30*time.Second)
	err = conn.QueryRow(lock, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", o.Schema+":auth-events:"+tenant).Scan(&acquired)
	finishLock()
	if err != nil {
		return err
	}
	if !acquired {
		return nil
	}
	if err := r.resyncDue(ctx); err != nil {
		return err
	}
	table := pgx.Identifier{o.Schema, "auth_event_cursors"}.Sanitize()
	for _, authority := range []bool{false, true} {
		stream := "tenant:" + tenant
		if authority {
			stream = "authority"
		}
		var after string
		read, finishRead := context.WithTimeout(ctx, 30*time.Second)
		err := o.Pool.QueryRow(read, "SELECT cursor FROM "+table+" WHERE stream=$1", stream).Scan(&after)
		finishRead()
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		for batch := 0; batch < 10; batch++ {
			// Replay alone cannot recover history older than retention. The
			// current state of the Reconcile statuses is synced before first
			// use or after an operator resets an expired tenant stream.
			if after == "" && !authority {
				if err := r.reconcile(ctx); err != nil {
					return err
				}
			}
			fetch, finishFetch := context.WithTimeout(ctx, 30*time.Second)
			page, err := r.client.ListEvents(fetch, iam.EventQuery{After: after, Limit: 100, Authority: authority})
			finishFetch()
			if errors.Is(err, iam.ErrEventCursorExpired) {
				// Current soft-deleted accounts cannot reconstruct missed hard
				// purges. Keep the checkpoint and make the gap explicit.
				return fmt.Errorf("auth event history expired for %s; account lifecycle recovery required: %w", stream, err)
			}
			if err != nil {
				return err
			}
			if page.NextCursor == "" {
				return errors.New("auth events: source omitted continuation cursor")
			}
			for _, event := range page.Events {
				if err := o.Handle(ctx, event); err != nil {
					if err := r.park(ctx, event.UserID, string(event.Kind), err, time.Time{}, 0); err != nil {
						return err
					}
				}
			}
			if page.NextCursor != after {
				checkpoint, finishCheckpoint := context.WithTimeout(ctx, 30*time.Second)
				_, err := o.Pool.Exec(checkpoint, "INSERT INTO "+table+" (stream,cursor) VALUES($1,$2) ON CONFLICT(stream) DO UPDATE SET cursor=EXCLUDED.cursor,updated_at=clock_timestamp()", stream, page.NextCursor)
				finishCheckpoint()
				if err != nil {
					return err
				}
			}
			after = page.NextCursor
			if !page.HasMore {
				break
			}
		}
	}
	return nil
}

// reconcile cannot reconstruct hard purges after event history expires, and it
// does not reveal accounts restored or unbanned inside a gap.
func (r *AccountEventLoop) reconcile(ctx context.Context) error {
	for _, status := range r.options.Reconcile {
		query := iam.UserQuery{Status: status}
		query.Page.Limit = 100
		for {
			read, finishRead := context.WithTimeout(ctx, 30*time.Second)
			page, err := r.client.ListUsers(read, query)
			finishRead()
			if err != nil {
				return err
			}
			for _, user := range page.Items {
				if err := r.options.Sync(ctx, user.ID); err != nil {
					return err
				}
			}
			if page.Next == "" {
				break
			}
			query.Page.Cursor = page.Next
		}
	}
	return nil
}
