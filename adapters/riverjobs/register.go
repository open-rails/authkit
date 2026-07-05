package riverjobs

import (
	"fmt"

	"github.com/open-rails/authkit"
	"github.com/riverqueue/river"
	"github.com/robfig/cron/v3"
)

// RegisterPurgeDeletedUsersWorker registers the purge worker into a River workers registry.
//
// Registration only maps the job's Kind to this worker; it does not make the
// host's River client fetch jobs on DefaultQueue (or whatever queue the host
// routes PurgeDeletedUsersArgs onto). The host must ALSO include that queue
// name in its own river.Config.Queues so its client actually polls it — see
// DefaultQueue's doc comment for the full shared-queue contract.
func RegisterPurgeDeletedUsersWorker(ws *river.Workers, svc authkit.Client, before BeforeUserHardDeleteFunc) {
	river.AddWorker(ws, NewPurgeDeletedUsersWorker(svc, before))
}

// AddPurgeDeletedUsersPeriodicJob adds a periodic job that enqueues the purge job on a cron schedule.
//
// Example cron: "0 4 * * *" (daily at 4 AM).
//
// The queue is whatever args.InsertOpts() resolves (args.Queue, or
// DefaultQueue if blank) — set args.Queue explicitly to route it elsewhere.
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
