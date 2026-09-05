package riverjobs

import (
	"github.com/open-rails/authkit"
	"github.com/riverqueue/river"
)

// RegisterPurgeDeletedUsersWorker registers the purge worker into a River workers registry.
//
// Registration only maps the job's Kind to this worker; it does not make the
// host's River client fetch jobs on DefaultQueue (or whatever queue the host
// routes PurgeDeletedUsersArgs onto). The host must ALSO include that queue
// name in its own river.Config.Queues so its client actually polls it — see
// DefaultQueue's doc comment for the full shared-queue contract.
func RegisterPurgeDeletedUsersWorker(ws *river.Workers, svc authkit.Client, before BeforeUserHardDeleteFunc) {
	river.AddWorker(ws, newPurgeDeletedUsersWorker(svc, before))
}
