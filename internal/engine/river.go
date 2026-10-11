package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	riverhelpers "github.com/open-rails/helpers/river"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

// riverConfig configures a River client AuthKit owns. It logs through the
// slog default, like the rest of AuthKit, instead of River's stdout logger.
func riverConfig(schema string) *river.Config {
	return &river.Config{Schema: schema, Logger: slog.Default()}
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
	// producer inserts AuthKit's jobs into RiverSchema in the caller's
	// transaction from New on; they wait there for whichever fleet runs them.
	producer   *river.Client[pgx.Tx]
	mu         sync.Mutex
	host       *pgxpool.Pool         // the host pool Start clones its own River's pool from
	client     *river.Client[pgx.Tx] // the fleet RiverJobs is bound to
	pool       *pgxpool.Pool         // Start's own River pool; nil on a host fleet
	own        bool                  // Start built and started client; Close stops it
	registered bool
	started    bool
	failed     bool
	closed     bool
}

// riverPoolConns sizes the pool of the River client Start builds: a fetcher per
// queue (five, one worker each), the leader elector, the periodic enqueuer
// and the completer. River's deadlines (5s to keep leadership, 10s to fetch)
// include waiting for a connection, so on the request pool a small or busy
// host pool made the leader resign and stopped every periodic job.
const riverPoolConns = 5

// initRiver builds the insert-only producer and records RiverSchema as this
// issuer's account-lifecycle fleet. It starts nothing: Start runs the jobs.
func (s *Engine) initRiver(ctx context.Context, host *pgxpool.Pool) error {
	if s.pg == nil {
		return nil
	}
	producer, err := river.NewClient(riverpgxv5.New(s.pg), riverConfig(s.cfg.Database.RiverSchema))
	if err != nil {
		return fmt.Errorf("authkit: construct River producer: %w", err)
	}
	s.maintenance = &riverMaintenance{producer: producer, host: host}
	return s.registerAccountDeliveryFleet(ctx, s.cfg.Database.RiverSchema)
}

// RiverJobs contributes AuthKit's jobs to one fleet: the host's, which it
// passes to Start with WithRiverClient, or the one Start builds itself. It
// neither constructs nor starts a client. Compose once; a failed composition
// needs a new Client.
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

func (s *Engine) registerRiver(cfg *river.Config) error {
	if cfg == nil {
		return fmt.Errorf("authkit: host River config is required")
	}
	if s.maintenance.registered {
		return fmt.Errorf("authkit: River workers already registered")
	}
	// New prepared River's tables in RiverSchema only.
	if cfg.Schema != s.cfg.Database.RiverSchema {
		return fmt.Errorf("authkit: River fleet schema %q differs from Config.Database.RiverSchema %q", cfg.Schema, s.cfg.Database.RiverSchema)
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
	if err := river.AddWorkerSafely(workers, &credentialSweepWorker{engine: s}); err != nil {
		return err
	}
	if err := river.AddWorkerSafely(workers, &backchannelLogoutWorker{engine: s}); err != nil {
		return err
	}
	cfg.Workers = workers
	if cfg.Queues == nil {
		cfg.Queues = make(map[string]river.QueueConfig)
	}
	if err := s.registerProvisioning(cfg); err != nil {
		return err
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
	sweepQueue := credentialSweepQueue(s.dbSchema(), s.cfg.Token.Issuer)
	if existing, ok := cfg.Queues[sweepQueue]; ok && existing.MaxWorkers < 1 {
		return fmt.Errorf("authkit: credential sweep queue %q requires workers", sweepQueue)
	}
	if _, ok := cfg.Queues[sweepQueue]; !ok {
		cfg.Queues[sweepQueue] = river.QueueConfig{MaxWorkers: 1}
	}
	finalizerQueue := accountFinalizerQueue(s.dbSchema())
	if existing, ok := cfg.Queues[finalizerQueue]; ok && existing.MaxWorkers < 1 {
		return fmt.Errorf("authkit: account finalization queue %q requires workers", finalizerQueue)
	}
	if _, ok := cfg.Queues[finalizerQueue]; !ok {
		cfg.Queues[finalizerQueue] = river.QueueConfig{MaxWorkers: 1}
	}
	interval := s.cfg.CleanupInterval
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

// Start starts the senders' health checks and River. Without a fleet it builds
// and starts AuthKit's own River client in RiverSchema; with one it requires
// the fleet RiverJobs is bound to and leaves its start to the host. It runs no
// DDL. A client without PostgreSQL (for example verify-only tests) has no jobs.
// The client running its issuer's fleet sets whether the issuer records
// account events (Deps.OnEvent).
func (s *Engine) Start(ctx context.Context, fleet *river.Client[pgx.Tx]) error {
	m := s.maintenance
	if m == nil {
		if fleet != nil {
			return errors.New("authkit: WithRiverClient requires Deps.Postgres")
		}
		s.startSenderHealth()
		return nil
	}
	m.mu.Lock()
	switch {
	case m.closed:
		m.mu.Unlock()
		return errors.New("authkit: client is closed")
	case m.started:
		m.mu.Unlock()
		return errors.New("authkit: already started")
	case m.failed:
		m.mu.Unlock()
		return errors.New("authkit: River composition failed; recreate the client")
	case fleet != nil && (!m.registered || m.client != fleet):
		m.mu.Unlock()
		return errors.New("authkit: WithRiverClient takes the fleet riverhelpers.New built with RiverJobs")
	case fleet == nil && m.registered:
		m.mu.Unlock()
		return errors.New("authkit: RiverJobs is composed into a host fleet; pass it to Start with WithRiverClient")
	}
	m.started = true
	m.mu.Unlock()
	if err := s.syncEventSubscription(ctx); err != nil {
		return fmt.Errorf("authkit: account event subscription: %w", err)
	}
	if err := s.pruneProvisioningTargets(ctx); err != nil {
		return fmt.Errorf("authkit: provisioning targets: %w", err)
	}
	if fleet == nil {
		if err := s.startOwnRiver(ctx); err != nil {
			return err
		}
	}
	s.startSenderHealth()
	return nil
}

// startOwnRiver composes RiverJobs into a client of AuthKit's own and starts
// it. Close, not ctx, stops it.
func (s *Engine) startOwnRiver(ctx context.Context) error {
	m := s.maintenance
	pool, err := schemaPool(m.host, s.dbSchema(), func(c *pgxpool.Config) {
		c.MaxConns, c.MinConns, c.MaxConnIdleTime = riverPoolConns, 0, time.Minute
	})
	if err != nil {
		return err
	}
	client, err := riverhelpers.New(ctx, pool, riverConfig(s.cfg.Database.RiverSchema), s.RiverJobs())
	if err != nil {
		pool.Close()
		return fmt.Errorf("authkit: construct River: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		pool.Close()
		return errors.New("authkit: client is closed")
	}
	m.pool, m.own = pool, true
	return client.Start(context.WithoutCancel(ctx))
}

// closeRiver revokes the bound producers and stops the client Start built,
// returning its pool for Close to release. A host fleet keeps running.
func (s *Engine) closeRiver(ctx context.Context) (*pgxpool.Pool, error) {
	m := s.maintenance
	if m == nil {
		return nil, nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, nil
	}
	m.closed = true
	client, pool, own := m.client, m.pool, m.own
	m.mu.Unlock()
	// Active lifecycle workers may still read the binding as cancellation
	// propagates. Never wait for their shutdown while holding that mutex.
	if own {
		return pool, client.StopAndCancel(ctx)
	}
	return nil, nil
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
