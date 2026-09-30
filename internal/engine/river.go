package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	riverhelpers "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"

	"github.com/open-rails/authkit/internal/db"
)

// riverConfig configures a River client AuthKit owns. It logs through the
// slog default, like the rest of AuthKit, instead of River's stdout logger.
func riverConfig(schema string) *river.Config {
	return &river.Config{Schema: schema, Logger: slog.Default()}
}

// RiverOwnership mirrors authkit.RiverOwnership.
type RiverOwnership struct{ fromHost bool }

// RiverFromHost selects a host-owned River fleet.
func RiverFromHost() *RiverOwnership { return &RiverOwnership{fromHost: true} }

// RiverConfig mirrors authkit.RiverConfig.
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
	pool       *pgxpool.Pool // the managed client's own; nil in host mode
	fromHost   bool
	registered bool
	failed     bool
	closed     bool
}

// riverPoolConns sizes the managed River client's own pool: a fetcher per
// queue (four, one worker each), the leader elector, the periodic enqueuer
// and the completer. River's deadlines (5s to keep leadership, 10s to fetch)
// include waiting for a connection, so on the request pool a small or busy
// host pool made the leader resign and stopped every periodic job.
const riverPoolConns = 4

func (s *Engine) initRiver(host *pgxpool.Pool, ownership *RiverOwnership) error {
	if s.pg == nil {
		return nil
	}
	s.maintenance = &riverMaintenance{fromHost: ownership != nil && ownership.fromHost}
	if s.maintenance.fromHost {
		return nil
	}
	pool, err := schemaPool(host, s.dbSchema(), func(c *pgxpool.Config) {
		c.MaxConns, c.MinConns, c.MaxConnIdleTime = riverPoolConns, 0, time.Minute
	})
	if err != nil {
		return err
	}
	client, err := riverhelpers.New(context.Background(), pool, riverConfig(s.cfg.River.Schema), s.RiverJobs())
	if err != nil {
		pool.Close()
		return fmt.Errorf("authkit: construct managed River: %w", err)
	}
	s.maintenance.client, s.maintenance.pool = client, pool
	return nil
}

// RiverJobs contributes AuthKit maintenance to one host-owned fleet. It does not
// construct or start a client. Compose once, before serving requests, and close
// the library if composition fails. The host controls Start and Stop.
func (s *Engine) RiverJobs() riverhelpers.Contribution {
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
	}, func(ctx context.Context, binding riverhelpers.Binding) error {
		if err := requireSameRiverDatabase(ctx, s.pg, binding.Pool); err != nil {
			return err
		}
		m := s.maintenance
		m.mu.Lock()
		if m.closed || m.failed {
			m.mu.Unlock()
			return fmt.Errorf("authkit: client closed during River composition")
		}
		m.client = binding.Client
		m.mu.Unlock()
		return s.registerAccountDeliveryFleet(ctx, binding.Client)
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

func (s *Engine) registerRiver(cfg *river.Config) error {
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
	if err := river.AddWorkerSafely(workers, &accountFinalizeWorker{engine: s}); err != nil {
		return err
	}
	if err := river.AddWorkerSafely(workers, &accountDeliveryWorker{engine: s}); err != nil {
		return err
	}
	if err := river.AddWorkerSafely(workers, &accountEventWorker{engine: s}); err != nil {
		return err
	}
	cfg.Workers = workers
	if cfg.Queues == nil {
		cfg.Queues = make(map[string]river.QueueConfig)
	}
	if _, ok := cfg.Queues[queue]; !ok {
		cfg.Queues[queue] = river.QueueConfig{MaxWorkers: 1}
	}
	deliveryQueue := accountDeliveryQueue(s.dbSchema(), s.cfg.Token.Issuer)
	if existing, ok := cfg.Queues[deliveryQueue]; ok && existing.MaxWorkers < 1 {
		return fmt.Errorf("authkit: account callback queue %q requires workers", deliveryQueue)
	}
	if _, ok := cfg.Queues[deliveryQueue]; !ok {
		cfg.Queues[deliveryQueue] = river.QueueConfig{MaxWorkers: 1}
	}
	eventQueue := accountEventQueue(s.dbSchema(), s.cfg.Token.Issuer)
	if existing, ok := cfg.Queues[eventQueue]; ok && existing.MaxWorkers < 1 {
		return fmt.Errorf("authkit: account event queue %q requires workers", eventQueue)
	}
	if _, ok := cfg.Queues[eventQueue]; !ok {
		cfg.Queues[eventQueue] = river.QueueConfig{MaxWorkers: 1}
	}
	finalizerQueue := accountFinalizerQueue(s.dbSchema())
	if existing, ok := cfg.Queues[finalizerQueue]; ok && existing.MaxWorkers < 1 {
		return fmt.Errorf("authkit: account finalization queue %q requires workers", finalizerQueue)
	}
	if _, ok := cfg.Queues[finalizerQueue]; !ok {
		cfg.Queues[finalizerQueue] = river.QueueConfig{MaxWorkers: 1}
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
func (s *Engine) Start(ctx context.Context) error {
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

func (s *Engine) closeRiver() {
	if s.maintenance == nil {
		return
	}
	m := s.maintenance
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	client, owned := m.client, !m.fromHost
	m.mu.Unlock()
	// Active lifecycle workers may still read the binding as cancellation
	// propagates. Never wait for their shutdown while holding that mutex.
	if client != nil && owned {
		_ = client.StopAndCancel(context.Background())
	}
	if m.pool != nil {
		m.pool.Close()
	}
}

type cleanupAuthStateArgs struct {
	Schema string `json:"schema"`
}

func (cleanupAuthStateArgs) Kind() string { return "authkit_cleanup_expired_auth_state" }

type cleanupAuthStateWorker struct {
	river.WorkerDefaults[cleanupAuthStateArgs]
	client *Engine
}

func (w *cleanupAuthStateWorker) Timeout(*river.Job[cleanupAuthStateArgs]) time.Duration {
	return 5 * time.Minute
}
func (w *cleanupAuthStateWorker) Work(ctx context.Context, job *river.Job[cleanupAuthStateArgs]) error {
	if job.Args.Schema != w.client.dbSchema() {
		return fmt.Errorf("authkit: cleanup job schema %q does not match worker schema %q", job.Args.Schema, w.client.dbSchema())
	}
	return w.client.cleanupExpiredAuthState(ctx)
}
