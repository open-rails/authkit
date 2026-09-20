package embedded

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/open-rails/authkit/internal/db"
)

// RiverOwnership declares who initializes and runs River. Nil means AuthKit
// owns its client. Use RiverFromHost for a fleet shared with other libraries.
// Pass the same declaration to Deps and MigrationOptions.
type RiverOwnership struct{ fromHost bool }

// RiverFromHost selects a host-owned River fleet. AuthKit never migrates,
// starts, or stops it. RegisterRiver installs AuthKit's workers and schedules
// into its configuration before the host calls river.NewClient.
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

type riverMaintenance struct {
	mu         sync.Mutex
	client     *river.Client[pgx.Tx]
	fromHost   bool
	registered bool
	closed     bool
}

func (s *Client) initRiver(ownership *RiverOwnership) error {
	if s.pg == nil {
		return nil
	}
	s.maintenance = &riverMaintenance{fromHost: ownership != nil && ownership.fromHost}
	if s.maintenance.fromHost {
		return nil
	}
	cfg := &river.Config{Schema: s.cfg.River.Schema}
	if err := s.registerRiver(cfg); err != nil {
		return err
	}
	client, err := river.NewClient(riverpgxv5.New(s.pg), cfg)
	if err != nil {
		return fmt.Errorf("authkit: construct managed River: %w", err)
	}
	s.maintenance.client = client
	return nil
}

// RegisterRiver installs the cleanup worker, queue and hourly schedule into a
// host-owned configuration. Call once, before river.NewClient, on every replica
// participating in the fleet. The host controls construction, Start and Stop.
// User hard-delete/purge is a separate opt-in adapter with its own host policy.
func (s *Client) RegisterRiver(cfg *river.Config) error {
	if s == nil || s.maintenance == nil {
		return fmt.Errorf("authkit: RegisterRiver requires PostgreSQL")
	}
	m := s.maintenance
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("authkit: client is closed")
	}
	if !m.fromHost {
		return fmt.Errorf("authkit: RegisterRiver requires Deps.River = RiverFromHost()")
	}
	return s.registerRiver(cfg)
}

func (s *Client) registerRiver(cfg *river.Config) error {
	if cfg == nil {
		return fmt.Errorf("authkit: host River config is required")
	}
	if s.maintenance.registered {
		return fmt.Errorf("authkit: River workers already registered")
	}
	queue := "authkit_maintenance_" + s.dbSchema()
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
func (s *Client) Start(ctx context.Context) error {
	if s == nil || s.maintenance == nil {
		return nil
	}
	m := s.maintenance
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("authkit: client is closed")
	}
	if !m.registered {
		return fmt.Errorf("authkit: call RegisterRiver before starting the host fleet")
	}
	if m.fromHost {
		return nil
	}
	return m.client.Start(ctx)
}

func (s *Client) closeRiver() {
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
	if m.client != nil {
		_ = m.client.StopAndCancel(context.Background())
	}
}

type cleanupAuthStateArgs struct {
	Schema string `json:"schema"`
}

func (cleanupAuthStateArgs) Kind() string { return "authkit_cleanup_expired_auth_state" }

type cleanupAuthStateWorker struct {
	river.WorkerDefaults[cleanupAuthStateArgs]
	client *Client
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
