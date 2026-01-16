package riverjobs

import (
	"context"
	"errors"
	"time"

	"github.com/PaulFidika/authkit/core"
	"github.com/riverqueue/river"
)

type PurgeDeletedUsersArgs struct {
	RetentionDays int `json:"retention_days,omitempty"`
	BatchSize     int `json:"batch_size,omitempty"`
}

func (PurgeDeletedUsersArgs) Kind() string { return "authkit_purge_deleted_users" }

func (args PurgeDeletedUsersArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: river.QueueDefault,
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
	svc    *core.Service
	before BeforeUserHardDeleteFunc
}

func NewPurgeDeletedUsersWorker(svc *core.Service, before BeforeUserHardDeleteFunc) *PurgeDeletedUsersWorker {
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
		if err := w.svc.HardDeleteUser(ctx, userID); err != nil {
			return err
		}
	}
	return nil
}

