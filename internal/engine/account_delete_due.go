package engine

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/open-rails/authkit/internal/db"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// Account deletion deadlines live in account_deletions, not in one future
// River row per account. Each issuer's daily job catches up after downtime too.
type accountDeleteDueArgs struct {
	Schema string `json:"schema"`
	Issuer string `json:"issuer"`
}

func (accountDeleteDueArgs) Kind() string { return "authkit_account_delete_due" }

func accountDeleteDueQueue(schema, issuer string) string {
	return accountScopedQueue("authkit_delete_due-", schema, issuer)
}

func (a accountDeleteDueArgs) InsertOpts() river.InsertOpts {
	queue := maintenanceQueue(a.Schema)
	if a.Issuer != "" {
		queue = accountDeleteDueQueue(a.Schema, a.Issuer)
	}
	return river.InsertOpts{
		Queue: queue,
		// A completed run must never suppress a restart's catch-up scan.
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByQueue: true, ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning,
			rivertype.JobStateRetryable, rivertype.JobStateScheduled,
		}},
	}
}

type accountDeleteDueWorker struct {
	river.WorkerDefaults[accountDeleteDueArgs]
	engine *Engine
}

func (w *accountDeleteDueWorker) Timeout(*river.Job[accountDeleteDueArgs]) time.Duration {
	return 5 * time.Minute
}

func (w *accountDeleteDueWorker) Work(ctx context.Context, job *river.Job[accountDeleteDueArgs]) error {
	if job.Args.Schema != w.engine.dbSchema() {
		return river.JobCancel(fmt.Errorf("authkit: account deletion sweep scope mismatch"))
	}
	if job.Args.Issuer == "" {
		return w.engine.scheduleAccountCleanups(ctx)
	}
	if job.Args.Issuer != w.engine.cfg.Token.Issuer {
		return river.JobCancel(fmt.Errorf("authkit: account cleanup issuer mismatch"))
	}
	return w.engine.deleteDueAccounts(ctx)
}

// River runs periodic constructors only on its elected leader. Every replica
// therefore registers the same dispatcher; it schedules one coalesced batch
// per issuer in this River fleet, never one job per account or event.
func (s *Engine) scheduleAccountCleanups(ctx context.Context) error {
	issuers, err := s.q.AccountCleanupFleetIssuers(ctx, s.cfg.Database.RiverSchema)
	if err != nil {
		return err
	}
	for _, issuer := range issuers {
		if err := s.scheduleAccountCleanup(ctx, issuer); err != nil {
			return err
		}
	}
	return nil
}

func (s *Engine) scheduleAccountCleanup(ctx context.Context, issuer string) error {
	_, err := s.maintenance.producer.Insert(ctx, accountDeleteDueArgs{Schema: s.dbSchema(), Issuer: issuer}, nil)
	return err
}

func (s *Engine) deleteDueAccounts(ctx context.Context) error {
	const batchSize = 100
	// Fix the upper bound for this pass. Keyset pagination visits every due
	// record once even when it fails; one blocked account cannot starve others.
	dueAt, err := s.q.StatementTimestamp(ctx)
	if err != nil {
		return err
	}
	cursor := db.AccountDeletionsDueParams{DueAt: dueAt, AfterPurgeAt: time.Time{}, AfterID: "00000000-0000-0000-0000-000000000000", BatchSize: batchSize}
	for {
		batch, err := s.q.AccountDeletionsDue(ctx, cursor)
		if err != nil {
			return err
		}
		for _, record := range batch {
			if err := ctx.Err(); err != nil {
				return err
			}
			// finalizeAccountDeletion locks authority, user and deletion rows and
			// checks the current state again. Concurrent sweeps, restores and
			// callback completions therefore cannot bypass the recovery window.
			if err := s.finalizeAccountDeletion(ctx, record.ID, record.State == "finalizing"); err != nil {
				slog.ErrorContext(ctx, "authkit: due account deletion will retry on next daily sweep", "deletion_id", record.ID, "error", err)
			}
			cursor.AfterPurgeAt, cursor.AfterID = record.PurgeAt, record.ID
		}
		if len(batch) < batchSize {
			break
		}
	}
	return s.completeDueAccountCleanups(ctx, dueAt)
}

// Every issuer runs its own daily/startup pass. A missing application leaves
// its receipts pending; another issuer can never mark that cleanup complete.
func (s *Engine) completeDueAccountCleanups(ctx context.Context, dueAt time.Time) error {
	var after int64
	for {
		rows, err := s.q.AccountCleanupsDue(ctx, db.AccountCleanupsDueParams{Issuer: s.cfg.Token.Issuer, DueAt: dueAt, AfterID: after})
		if err != nil {
			return err
		}
		for _, id := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := s.runAccountCleanup(ctx, id); err != nil {
				slog.ErrorContext(ctx, "authkit: account cleanup will retry on the next daily sweep", "cleanup_id", id, "error", err)
			}
			after = id
		}
		if len(rows) < 100 {
			return nil
		}
	}
}
