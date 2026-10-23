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
	"github.com/riverqueue/river/rivertype"
)

const accountCleanupInterval = 24 * time.Hour

// Account deletion deadlines live in account_deletions, not in one future
// River row per account. Each issuer's daily job catches up after downtime too.
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
	queue := maintenanceQueue(a.Schema)
	if a.Issuer != "" {
		queue = accountDeleteDueQueue(a.Schema, a.Issuer)
	}
	return river.InsertOpts{
		Queue: queue,
		// Explicit hard-purge requests can follow a recent completed scan.
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
	if job.Args.After != 0 {
		previous, err := river.ClientFromContext[pgx.Tx](ctx).JobGet(ctx, job.Args.After)
		if err != nil && !errors.Is(err, river.ErrNotFound) {
			return err
		}
		if err == nil && previous.State == rivertype.JobStateRunning {
			return river.JobSnooze(time.Second)
		}
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
	for _, issuer := range slices.Sorted(slices.Values(issuers)) {
		if err := s.scheduleAccountCleanup(ctx, issuer); err != nil {
			return err
		}
	}
	return nil
}

func (s *Engine) scheduleAccountCleanup(ctx context.Context, issuer string) error {
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Startup runs on every replica, including followers. Serialize this
	// issuer's due check and insert so concurrent starts cannot create work
	// between another replica's completed check and insert.
	key := "authkit.account-cleanup." + s.cfg.Database.RiverSchema + "." + s.dbSchema() + "." + issuer
	if err := db.New(tx).AdvisoryXactLock(ctx, key); err != nil {
		return err
	}
	var recent bool
	jobs := pgx.Identifier{s.cfg.Database.RiverSchema, "river_job"}.Sanitize()
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM `+jobs+`
		WHERE kind='authkit_account_delete_due' AND args->>'schema'=$1 AND args->>'issuer'=$2
		AND (state IN ('available','pending','running','retryable','scheduled')
			OR greatest(created_at,attempted_at) > statement_timestamp() - $3 * interval '1 second'))`,
		s.dbSchema(), issuer, accountCleanupInterval.Seconds()).Scan(&recent); err != nil {
		return err
	}
	if recent {
		return nil
	}
	if err := s.insertAccountCleanup(ctx, tx, s.maintenance.producer, issuer); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Engine) insertAccountCleanup(ctx context.Context, tx pgx.Tx, client *river.Client[pgx.Tx], issuer string) error {
	args := accountDeleteDueArgs{Schema: s.dbSchema(), Issuer: issuer}
	for {
		var result *rivertype.JobInsertResult
		var err error
		if tx == nil {
			result, err = client.Insert(ctx, args, nil)
		} else {
			result, err = client.InsertTx(ctx, tx, args, nil)
		}
		if err != nil || !result.UniqueSkippedAsDuplicate || result.Job.State != rivertype.JobStateRunning {
			return err
		}
		args.After = result.Job.ID
	}
}

// An explicit hard-purge request should not wait for tomorrow's sweep. Its
// transaction queues a bounded batch per issuer, never a job per account.
// A running scan may have passed the new receipt, so retain one follow-up.
func (s *Engine) scheduleAccountCleanupTx(ctx context.Context, tx pgx.Tx, issuers []string) error {
	for _, issuer := range slices.Sorted(slices.Values(issuers)) {
		schema, err := s.qtx(tx).AccountDeliveryFleetSchemaForShare(ctx, issuer)
		if err != nil {
			return err
		}
		client, err := s.fleetProducer(schema)
		if err != nil {
			return err
		}
		if err := s.insertAccountCleanup(ctx, tx, client, issuer); err != nil {
			return err
		}
	}
	return nil
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
