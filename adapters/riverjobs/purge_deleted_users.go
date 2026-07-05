package riverjobs

import (
	"context"
	"errors"
	"time"

	"github.com/open-rails/authkit"
	"github.com/riverqueue/river"
)

// DefaultQueue is the River queue AuthKit's jobs insert onto when a job's
// Queue field is left blank. It is a queue named after AuthKit — never
// river.QueueDefault — so that a host's own jobs on the shared `default`
// queue can never cross-fetch AuthKit's jobs (or vice versa): River fetches
// work by queue name only, and a client that pulls a kind it has no worker
// for burns a failed attempt (UnknownJobKindError).
//
// Every host embedding an AuthKit River job (e.g. via
// RegisterPurgeDeletedUsersWorker) MUST add this queue name to its own
// river.Config.Queues map so its client actually polls it, in addition to
// registering the worker (registration alone only maps kind->worker; it does
// not make the client fetch from the queue). In a shared-DB fleet, every host
// that authkit purges users for should subscribe to and register against the
// SAME queue name: the periodic job is unique by args+queue+period
// (UniqueOpts below), so multiple hosts scheduling it against one shared
// queue safely dedupe to a single row per period instead of each host
// needing its own queue.
const DefaultQueue = "authkit"

type PurgeDeletedUsersArgs struct {
	RetentionDays int `json:"retention_days,omitempty"`
	BatchSize     int `json:"batch_size,omitempty"`

	// Queue overrides the River queue this job is inserted onto. Empty means
	// DefaultQueue. Routing-only: deliberately excluded from the persisted
	// job args (json:"-") so it never affects the ByArgs uniqueness hash —
	// ByQueue below already makes queue part of the dedup key.
	Queue string `json:"-"`
}

func (PurgeDeletedUsersArgs) Kind() string { return "authkit_purge_deleted_users" }

func (args PurgeDeletedUsersArgs) InsertOpts() river.InsertOpts {
	queue := args.Queue
	if queue == "" {
		queue = DefaultQueue
	}
	return river.InsertOpts{
		Queue: queue,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 24 * time.Hour,
			ByQueue:  true,
		},
	}
}

type BeforeUserHardDeleteFunc func(ctx context.Context, userID string) error

// PurgeDeletedUsersWorker hard-deletes users that were soft-deleted more than RetentionDays ago.
//
// The host application may provide an optional BeforeUserHardDelete hook to delete/anonymize
// app-domain data (likes/favorites/comments, etc.) before AuthKit deletes the user row.
type PurgeDeletedUsersWorker struct {
	river.WorkerDefaults[PurgeDeletedUsersArgs]
	svc    authkit.Client
	before BeforeUserHardDeleteFunc
}

func NewPurgeDeletedUsersWorker(svc authkit.Client, before BeforeUserHardDeleteFunc) *PurgeDeletedUsersWorker {
	return &PurgeDeletedUsersWorker{svc: svc, before: before}
}

func (w *PurgeDeletedUsersWorker) Timeout(*river.Job[PurgeDeletedUsersArgs]) time.Duration {
	return 10 * time.Minute
}

func (w *PurgeDeletedUsersWorker) Work(ctx context.Context, job *river.Job[PurgeDeletedUsersArgs]) error {
	if w == nil || w.svc == nil {
		return errors.New("authkit purge: service not configured")
	}
	retention := job.Args.RetentionDays
	if retention <= 0 {
		retention = 30
	}
	batch := job.Args.BatchSize
	if batch <= 0 {
		batch = 500
	}

	cutoff := time.Now().AddDate(0, 0, -retention)
	ids, err := w.svc.ListUsersDeletedBefore(ctx, cutoff, batch)
	if err != nil {
		return err
	}
	for _, userID := range ids {
		if w.before != nil {
			if err := w.before(ctx, userID); err != nil {
				return err
			}
		}
		results, err := w.svc.HardDeleteUsers(ctx, []string{userID})
		if err == nil && len(results) == 1 {
			err = results[0].Err
		}
		if err != nil {
			return err
		}
	}
	return nil
}
