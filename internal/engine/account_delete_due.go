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
// River row per account. The single daily job catches up after downtime too.
type accountDeleteDueArgs struct {
	Schema string `json:"schema"`
}

func (accountDeleteDueArgs) Kind() string { return "authkit_account_delete_due" }

func (a accountDeleteDueArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: maintenanceQueue(a.Schema),
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
		return river.JobCancel(fmt.Errorf("authkit: account deletion sweep schema mismatch"))
	}
	return w.engine.deleteDueAccounts(ctx)
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
			return nil
		}
	}
}
