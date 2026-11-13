package engine

// Due jobs run when their work is due, not on a clock (#478). Each key has
// one job, scheduled at the earliest instant its work needs: whoever creates
// the work schedules it in the same transaction, and a run with more work
// later snoozes until then. A change committed while the key's job runs gets
// one follow-up (After), which hands the next instant back to the key's job.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// dueFloor is the shortest snooze: River snoozes on this process's clock,
// while due instants come from the database's.
const dueFloor = time.Second

// dueUnique keeps one job per key until it completes.
var dueUnique = river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
	rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning,
	rivertype.JobStateRetryable, rivertype.JobStateScheduled,
}}

type dueArgs interface {
	river.JobArgs
	river.JobArgsWithInsertOpts
	// predecessor is the running job this one follows; 0 for the key's job.
	predecessor() int64
	following(id int64) dueArgs
}

// scheduleDue makes args' job run by at, committing with tx. A later one is
// moved up; a running one gets a follow-up, since it may have read before tx.
func scheduleDue(ctx context.Context, tx pgx.Tx, client *river.Client[pgx.Tx], args dueArgs, at time.Time) error {
	for range 4 {
		opts := args.InsertOpts()
		if at.After(time.Now()) {
			opts.ScheduledAt = at // River holds any ScheduledAt for its scheduler, even a past one
		}
		res, err := client.InsertTx(ctx, tx, args, &opts)
		if err != nil || !res.UniqueSkippedAsDuplicate {
			return err
		}
		switch job := res.Job; {
		case job.State == rivertype.JobStateRunning:
			args = args.following(job.ID)
		case job.State != rivertype.JobStateAvailable && job.ScheduledAt.After(at):
			if _, err := client.JobDeleteTx(ctx, tx, job.ID); err != nil && !errors.Is(err, rivertype.ErrJobRunning) && !errors.Is(err, rivertype.ErrNotFound) {
				return err
			}
		default:
			return nil
		}
	}
	return fmt.Errorf("authkit: %s: too many runs in flight", args.Kind())
}

// awaitPredecessor holds a follow-up while the job it follows still runs: a
// moment in process, as River records a finished run a little later, then
// by snoozing.
func awaitPredecessor(ctx context.Context, after int64) error {
	if after == 0 {
		return nil
	}
	client := river.ClientFromContext[pgx.Tx](ctx)
	for range 50 {
		previous, err := client.JobGet(ctx, after)
		if errors.Is(err, river.ErrNotFound) || err == nil && previous.State != rivertype.JobStateRunning {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return river.JobSnooze(dueFloor)
}

// afterRun ends a run whose work is next due at next (nil: none). The key's
// job snoozes until then; a follow-up schedules the key's job and is done.
func (s *Engine) afterRun(ctx context.Context, args dueArgs, base dueArgs, next *time.Time) error {
	switch {
	case next == nil:
		return nil
	case args.predecessor() == 0:
		return river.JobSnooze(max(time.Until(*next), dueFloor))
	}
	client := river.ClientFromContext[pgx.Tx](ctx)
	return pgx.BeginFunc(ctx, s.pg, func(tx pgx.Tx) error { return scheduleDue(ctx, tx, client, base, *next) })
}

// earliest keeps the earlier of next and t.
func earliest(next *time.Time, t time.Time) *time.Time {
	if next == nil || t.Before(*next) {
		return &t
	}
	return next
}
