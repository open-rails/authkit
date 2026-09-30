package password

import (
	"context"
	"runtime"
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
	"golang.org/x/sync/semaphore"
)

// Password hashing is bounded process-wide (ak#417). Argon2id allocates its
// whole memory cost up front, so each hash or verify holds that cost of one
// shared budget while it runs, and a bcrypt verify one default Argon2id share
// (its cost is CPU). The budget is one default Argon2id computation per CPU,
// at least two; a stored hash costlier than the whole budget runs alone. A
// computation that cannot start within busyWait fails with ErrBusy, so a
// flood of password attempts queues briefly and is then turned away instead
// of exhausting memory.

const busyWait = time.Second

// ErrBusy is 503 server_busy with Retry-After: the password-hashing budget
// stayed full for busyWait.
var ErrBusy = errmodel.E(errmodel.CodeServerBusy, errmodel.WithDetails(errmodel.RetryAfter{RetryAfterSeconds: int64(busyWait / time.Second)}))

var work = newBudget(runtime.GOMAXPROCS(0))

type budget struct {
	sem   *semaphore.Weighted
	limit int64 // KiB
}

func newBudget(cpus int) budget {
	limit := int64(max(2, cpus)) * int64(DefaultParams().Memory)
	return budget{sem: semaphore.NewWeighted(limit), limit: limit}
}

// run runs fn holding cost KiB of the budget.
func (b budget) run(ctx context.Context, cost uint32, fn func()) error {
	weight := min(int64(cost), b.limit)
	wait, cancel := context.WithTimeout(ctx, busyWait)
	defer cancel()
	if err := b.sem.Acquire(wait, weight); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrBusy
	}
	defer b.sem.Release(weight)
	fn()
	return nil
}

// InFlightLimit is the most memory, in bytes, password hashing holds at
// once: the budget, or a single hash of the costliest accepted parameters.
func InFlightLimit() int64 { return max(work.limit, maxMemoryKiB) * 1024 }
