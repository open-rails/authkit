package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
	"github.com/riverqueue/river"
)

// Failed cleanup is retried after as long as it has been overdue, from a
// minute up to a day.
const (
	accountCleanupMinRetry = time.Minute
	accountCleanupMaxRetry = 24 * time.Hour
)

// Account deletion deadlines live in account_deletions, not in one River job
// per account. Each issuer has one batch job (a due job), due at the earliest
// purge_at of the deletions it receives: the transaction that sets a purge_at
// schedules it, and each run snoozes until the next one.
type accountDeleteDueArgs struct {
	Schema string `json:"schema"`
	Issuer string `json:"issuer"`
	After  int64  `json:"after,omitempty"`
}

func (accountDeleteDueArgs) Kind() string { return "authkit_account_delete_due" }

func accountDeleteDueQueue(schema, issuer string) string {
	return accountScopedQueue("authkit_delete_due-", schema, issuer)
}

func (a accountDeleteDueArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: accountDeleteDueQueue(a.Schema, a.Issuer), UniqueOpts: dueUnique}
}

func (a accountDeleteDueArgs) predecessor() int64 { return a.After }

func (a accountDeleteDueArgs) following(id int64) dueArgs { a.After = id; return a }

type accountDeleteDueWorker struct {
	river.WorkerDefaults[accountDeleteDueArgs]
	engine *Engine
}

func (w *accountDeleteDueWorker) Timeout(*river.Job[accountDeleteDueArgs]) time.Duration {
	return 5 * time.Minute
}

func (w *accountDeleteDueWorker) Work(ctx context.Context, job *river.Job[accountDeleteDueArgs]) error {
	s := w.engine
	if job.Args.Schema != s.dbSchema() || job.Args.Issuer != s.cfg.Token.Issuer {
		return river.JobCancel(fmt.Errorf("authkit: account cleanup routed to a different application"))
	}
	if err := awaitPredecessor(ctx, job.Args.After); err != nil {
		return err
	}
	next, err := s.deleteDueAccounts(ctx)
	if err != nil {
		return err
	}
	return s.afterRun(ctx, job.Args, accountDeleteDueArgs{Schema: job.Args.Schema, Issuer: job.Args.Issuer}, next)
}

// scheduleAccountCleanupTx makes each issuer's batch due by at in its own
// fleet, committing with tx: a deletion's purge_at, or now.
func (s *Engine) scheduleAccountCleanupTx(ctx context.Context, tx pgx.Tx, issuers []string, at time.Time) error {
	for _, issuer := range slices.Sorted(slices.Values(issuers)) {
		schema, err := s.qtx(tx).AccountDeliveryFleetSchemaForShare(ctx, issuer)
		if err != nil {
			return err
		}
		client, err := s.fleetProducer(schema)
		if err != nil {
			return err
		}
		if err := scheduleDue(ctx, tx, client, accountDeleteDueArgs{Schema: s.dbSchema(), Issuer: issuer}, at); err != nil {
			return err
		}
	}
	return nil
}

// catchUpAccountCleanup schedules this issuer's batch at its earliest pending
// work, which a deletion recorded by an earlier release has no job for.
func (s *Engine) catchUpAccountCleanup(ctx context.Context) error {
	at, err := s.q.AccountCleanupNextDue(ctx, db.AccountCleanupNextDueParams{Issuer: s.cfg.Token.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error {
		return scheduleDue(ctx, tx, s.maintenance.producer, accountDeleteDueArgs{Schema: s.dbSchema(), Issuer: s.cfg.Token.Issuer}, at)
	})
}

// deleteDueAccounts finalizes the deletions due at the pass's cutoff, runs
// this issuer's due cleanup, and returns when its batch is next due: the next
// purge_at it receives, or sooner to retry a failure.
func (s *Engine) deleteDueAccounts(ctx context.Context) (*time.Time, error) {
	const batchSize = 100
	// Fix the upper bound for this pass. Keyset pagination visits every due
	// record once even when it fails; one blocked account cannot starve others.
	dueAt, err := s.q.StatementTimestamp(ctx)
	if err != nil {
		return nil, err
	}
	var failed *time.Time // the earliest purge_at this pass failed
	cursor := db.AccountDeletionsDueParams{DueAt: dueAt, AfterPurgeAt: time.Time{}, AfterID: "00000000-0000-0000-0000-000000000000", BatchSize: batchSize}
	for {
		batch, err := s.q.AccountDeletionsDue(ctx, cursor)
		if err != nil {
			return nil, err
		}
		for _, record := range batch {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			// finalizeAccountDeletion locks authority, user and deletion rows and
			// checks the current state again. Concurrent sweeps, restores and
			// callback completions therefore cannot bypass the recovery window.
			if err := s.finalizeAccountDeletion(ctx, record.ID, record.State == "finalizing"); err != nil {
				slog.ErrorContext(ctx, "authkit: due account deletion failed; will retry", "deletion_id", record.ID, "error", err)
				failed = earliest(failed, record.PurgeAt)
			}
			cursor.AfterPurgeAt, cursor.AfterID = record.PurgeAt, record.ID
		}
		if len(batch) < batchSize {
			break
		}
	}
	cleanupFailed, err := s.completeDueAccountCleanups(ctx, dueAt)
	if err != nil {
		return nil, err
	}
	if cleanupFailed != nil {
		failed = earliest(failed, *cleanupFailed)
	}
	var next *time.Time
	at, err := s.q.AccountCleanupNextDue(ctx, db.AccountCleanupNextDueParams{Issuer: s.cfg.Token.Issuer, AfterAt: dueAt})
	switch {
	case err == nil:
		next = &at
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	}
	if failed != nil {
		next = earliest(next, dueAt.Add(min(max(dueAt.Sub(*failed), accountCleanupMinRetry), accountCleanupMaxRetry)))
	}
	return next, nil
}

// Every issuer runs its own pass. A missing application leaves its receipts
// pending; another issuer can never mark that cleanup complete. It returns
// the earliest purge_at whose cleanup failed.
func (s *Engine) completeDueAccountCleanups(ctx context.Context, dueAt time.Time) (*time.Time, error) {
	var after int64
	var failed *time.Time
	for {
		rows, err := s.q.AccountCleanupsDue(ctx, db.AccountCleanupsDueParams{Issuer: s.cfg.Token.Issuer, DueAt: dueAt, AfterID: after})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err := s.runAccountCleanup(ctx, row.ID); err != nil {
				slog.ErrorContext(ctx, "authkit: account cleanup failed; will retry", "cleanup_id", row.ID, "error", err)
				failed = earliest(failed, row.PurgeAt)
			}
			after = row.ID
		}
		if len(rows) < 100 {
			return failed, nil
		}
	}
}
