package riverjobs

import (
	"fmt"

	"github.com/PaulFidika/authkit/core"
	"github.com/riverqueue/river"
	"github.com/robfig/cron/v3"
)

// RegisterPurgeDeletedUsersWorker registers the purge worker into a River workers registry.
func RegisterPurgeDeletedUsersWorker(ws *river.Workers, svc *core.Service, before BeforeUserHardDeleteFunc) {
	river.AddWorker(ws, NewPurgeDeletedUsersWorker(svc, before))
}

// AddPurgeDeletedUsersPeriodicJob adds a periodic job that enqueues the purge job on a cron schedule.
//
// Example cron: "0 4 * * *" (daily at 4 AM).
func AddPurgeDeletedUsersPeriodicJob[T any](client *river.Client[T], cronSpec string, args PurgeDeletedUsersArgs, runOnStart bool) error {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(cronSpec)
	if err != nil {
		return fmt.Errorf("invalid cron schedule '%s': %w", cronSpec, err)
	}
	opts := args.InsertOpts()
	_ = client.PeriodicJobs().Add(
		river.NewPeriodicJob(
			schedule,
			func() (river.JobArgs, *river.InsertOpts) { return args, &opts },
			&river.PeriodicJobOpts{RunOnStart: runOnStart},
		),
	)
	return nil
}

