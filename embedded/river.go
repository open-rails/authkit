package embedded

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	riverhelpers "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"

	"github.com/open-rails/authkit/internal/db"
)

// RiverOwnership declares who initializes and runs River. Nil means AuthKit
// owns its client. Use RiverFromHost for a fleet shared with other libraries.
// Pass the same declaration to Deps and MigrationOptions.
type RiverOwnership struct{ fromHost bool }

// RiverFromHost selects a host-owned River fleet. AuthKit never migrates,
// starts, or stops it. Pass RiverJobs() to riverhelpers.New to register AuthKit's
// workers and schedules in the host fleet.
func RiverFromHost() *RiverOwnership { return &RiverOwnership{fromHost: true} }

// RiverConfig configures PostgreSQL maintenance. The default schema is public
// and cleanup runs hourly. Managed clients require a fleet with the same full
// worker/schedule set; unrelated libraries sharing a schema must compose one
// host-owned configuration so whichever replica leads has every schedule.
type RiverConfig struct {
	Schema          string
	CleanupInterval time.Duration
}

func normalizeRiverConfig(cfg RiverConfig) (RiverConfig, error) {
	cfg.Schema = strings.TrimSpace(cfg.Schema)
	if cfg.Schema == "" {
		cfg.Schema = "public"
	}
	if !db.ValidSchemaName(cfg.Schema) {
		return cfg, fmt.Errorf("authkit: invalid River.Schema %q", cfg.Schema)
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Hour
	}
	if cfg.CleanupInterval < time.Second {
		return cfg, fmt.Errorf("authkit: River.CleanupInterval must be at least one second")
	}
	return cfg, nil
}

// maintenanceQueue preserves existing readable names where River accepts them.
// Schema identifiers can be 63 bytes and allow underscore patterns that River
// queues do not. The hyphen distinguishes hashed names from readable schemas.
func maintenanceQueue(schema string) string {
	const prefix = "authkit_maintenance"
	readable := prefix + "_" + schema
	if len(readable) <= 64 && !strings.HasPrefix(schema, "_") && !strings.HasSuffix(schema, "_") && !strings.Contains(schema, "__") {
		return readable
	}
	digest := sha256.Sum256([]byte(schema))
	return prefix + "-" + hex.EncodeToString(digest[:22])
}

type riverMaintenance struct {
	mu         sync.Mutex
	client     *river.Client[pgx.Tx]
	fromHost   bool
	registered bool
	failed     bool
	closed     bool
}

func (s *Runtime) initRiver(ownership *RiverOwnership) error {
	if s.pg == nil {
		return nil
	}
	s.maintenance = &riverMaintenance{fromHost: ownership != nil && ownership.fromHost}
	if s.maintenance.fromHost {
		return nil
	}
	client, err := riverhelpers.New(context.Background(), s.pg, &river.Config{Schema: s.cfg.River.Schema}, s.RiverJobs())
	if err != nil {
		return fmt.Errorf("authkit: construct managed River: %w", err)
	}
	s.maintenance.client = client
	return nil
}

// RiverJobs contributes AuthKit maintenance to one host-owned fleet. It does not
// construct or start a client. Compose once, before serving requests, and close
// the library if composition fails. The host controls Start and Stop.
func (s *Runtime) RiverJobs() riverhelpers.Contribution {
	claimed := false
	return riverhelpers.NewContribution("authkit", func(_ context.Context, cfg *river.Config) error {
		if s == nil || s.maintenance == nil {
			return fmt.Errorf("authkit: RiverJobs requires PostgreSQL")
		}
		m := s.maintenance
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.closed {
			return fmt.Errorf("authkit: client is closed")
		}
		if m.failed || m.registered {
			return fmt.Errorf("authkit: River jobs already composed; recreate failed runtimes")
		}
		claimed = true
		return s.registerRiver(cfg)
	}, func(_ context.Context, binding riverhelpers.Binding) error {
		m := s.maintenance
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.closed || m.failed {
			return fmt.Errorf("authkit: client closed during River composition")
		}
		m.client = binding.Client
		return nil
	}, func() error {
		if !claimed || s == nil || s.maintenance == nil {
			return nil
		}
		m := s.maintenance
		m.mu.Lock()
		defer m.mu.Unlock()
		m.failed = true
		m.client = nil
		return nil
	})
}

func (s *Runtime) registerRiver(cfg *river.Config) error {
	if cfg == nil {
		return fmt.Errorf("authkit: host River config is required")
	}
	if s.maintenance.registered {
		return fmt.Errorf("authkit: River workers already registered")
	}
	queue := maintenanceQueue(s.dbSchema())
	if existing, ok := cfg.Queues[queue]; ok && existing.MaxWorkers < 1 {
		return fmt.Errorf("authkit: maintenance queue %q requires at least one worker", queue)
	}
	workers := cfg.Workers
	if workers == nil {
		workers = river.NewWorkers()
	}
	if err := river.AddWorkerSafely(workers, &cleanupAuthStateWorker{client: s}); err != nil {
		return fmt.Errorf("authkit: register cleanup worker: %w", err)
	}
	cfg.Workers = workers
	if cfg.Queues == nil {
		cfg.Queues = make(map[string]river.QueueConfig)
	}
	if _, ok := cfg.Queues[queue]; !ok {
		cfg.Queues[queue] = river.QueueConfig{MaxWorkers: 1}
	}
	interval := s.cfg.River.CleanupInterval
	cfg.PeriodicJobs = append(cfg.PeriodicJobs, river.NewPeriodicJob(
		river.PeriodicInterval(interval),
		func() (river.JobArgs, *river.InsertOpts) {
			return cleanupAuthStateArgs{Schema: s.dbSchema()}, &river.InsertOpts{
				Queue:      queue,
				UniqueOpts: river.UniqueOpts{ByArgs: true, ByQueue: true, ByPeriod: interval},
			}
		}, &river.PeriodicJobOpts{ID: "authkit_cleanup_" + s.dbSchema(), RunOnStart: true},
	))
	s.maintenance.registered = true
	return nil
}

// Start starts AuthKit-owned maintenance after privileged initialization. It
// performs no migrations. In host mode it checks registration only: the host
// starts its shared client after composing every library's worker registry.
// A client without PostgreSQL (for example verify-only tests) has no jobs.
func (s *Runtime) Start(ctx context.Context) error {
	if s == nil || s.maintenance == nil {
		return nil
	}
	m := s.maintenance
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("authkit: client is closed")
	}
	if m.failed || !m.registered || m.client == nil {
		return fmt.Errorf("authkit: compose RiverJobs with riverhelpers.New before starting the host fleet")
	}
	if m.fromHost {
		return nil
	}
	return m.client.Start(ctx)
}

func (s *Runtime) closeRiver() {
	if s.maintenance == nil {
		return
	}
	m := s.maintenance
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	if m.client != nil && !m.fromHost {
		_ = m.client.StopAndCancel(context.Background())
	}
}

type cleanupAuthStateArgs struct {
	Schema string `json:"schema"`
}

func (cleanupAuthStateArgs) Kind() string { return "authkit_cleanup_expired_auth_state" }

type cleanupAuthStateWorker struct {
	river.WorkerDefaults[cleanupAuthStateArgs]
	client *Runtime
}

func (w *cleanupAuthStateWorker) Timeout(*river.Job[cleanupAuthStateArgs]) time.Duration {
	return 5 * time.Minute
}
func (w *cleanupAuthStateWorker) Work(ctx context.Context, job *river.Job[cleanupAuthStateArgs]) error {
	if job.Args.Schema != w.client.dbSchema() {
		return fmt.Errorf("authkit: cleanup job schema %q does not match worker schema %q", job.Args.Schema, w.client.dbSchema())
	}
	return w.client.CleanupExpiredAuthState(ctx)
}
