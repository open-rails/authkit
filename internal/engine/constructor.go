package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/pgsession"
	"github.com/open-rails/authkit/keys"
)

// New builds the engine: it normalizes cfg once (config.Normalize), resolves
// keys, waits for PostgreSQL (waitForPostgres), creates or upgrades the tables
// (Migrate, or validates them with SkipMigrations), then builds the store,
// River, the permission groups and the
// request authenticator. ctx bounds the boot-time database work. It fails
// only on what AuthKit cannot run safely with; a survivable problem switches
// off the feature it concerns and is reported by Probes. deps.Logger is set:
// authkit.New resolved it.
func New(ctx context.Context, cfg config.Config, deps config.Deps) (_ *Engine, err error) {
	log := deps.Logger
	norm, degraded, err := config.Normalize(cfg, deps)
	if err != nil {
		return nil, err
	}
	gs, err := config.CompileRoles(norm.Roles)
	if err != nil {
		return nil, err
	}
	dev, err := newDevelopmentKeys(norm.Issuer)
	if err != nil {
		return nil, err
	}
	src, owned, err := engineKeySource(deps.KeySource, dev, log)
	if err != nil {
		return nil, err
	}
	// A source with no active signer only verifies.
	signs := src.ActiveSigner() != nil
	totpKey, err := totpKeyOf(src)
	if err != nil {
		owned.Close()
		return nil, err
	}
	dev.report(log)
	s := &Engine{
		log:               log,
		cfg:               norm,
		passkeys:          config.Passkeys(norm.FrontendURL),
		keys:              src,
		totpKey:           totpKey,
		ownedKeySource:    owned,
		signs:             signs,
		schema:            norm.Database.Schema,
		groupSchema:       gs,
		solanaSNSResolver: newDefaultSolanaSNSResolver(),
		now:               time.Now,
		emailHealth:       senderHealth{recheck: make(chan struct{}, 1)},
		smsHealth:         senderHealth{recheck: make(chan struct{}, 1)},
	}
	defer func() {
		if err != nil {
			_ = s.Close(context.WithoutCancel(ctx))
		}
	}()
	for _, problem := range degraded {
		s.degrade(problem)
	}
	if deps.Postgres != nil {
		if deps.PostgresSession != nil {
			if deps.PostgresSession.ConnConfig == nil {
				return nil, errors.New("authkit: Deps.PostgresSession has no connection settings")
			}
			if err := pgsession.CheckPooled(deps.Postgres); err != nil {
				return nil, err
			}
		}
		if err := waitForPostgres(ctx, log, deps.Postgres); err != nil {
			return nil, err
		}
		if deps.PostgresSession != nil {
			if err := pgsession.CheckSearchPath(ctx, deps.Postgres, pgx.Identifier{"AuthKit_probe_" + rand.Text()}.Sanitize()+", public"); err != nil {
				return nil, err
			}
		}
		if norm.Database.SkipMigrations {
			if err := validateMigrations(ctx, log, deps.Postgres, norm.Database); err != nil {
				return nil, err
			}
		} else if err := migrateDirect(ctx, deps, func(pool *pgxpool.Pool) error {
			return Migrate(ctx, pool, norm.Database, MigrationOptions{Tenancy: norm.Tenancy, TenantID: norm.DefaultTenantID, Logger: log})
		}); err != nil {
			return nil, err
		}
		// Single-tenant, the database's one tenant is the default: settings
		// that name no tenant get it.
		if norm.Tenancy == config.TenancySingle {
			id, err := soleTenant(ctx, log, deps.Postgres, norm.Database, norm.DefaultTenantID, false)
			if err != nil {
				return nil, err
			}
			if err := config.BindDefaultTenant(&norm, id); err != nil {
				return nil, err
			}
			s.cfg = norm
		}
	}
	if err := s.applyDeps(deps); err != nil {
		return nil, err
	}
	if s.pg != nil && !norm.DefaultTenantID.IsZero() {
		if _, err := s.Tenant(ctx, norm.DefaultTenantID); err != nil {
			return nil, fmt.Errorf("authkit: configured default tenant: %w", err)
		}
	}
	if problem := s.secondFactorProblem(); problem != nil {
		s.degrade(problem)
	} else if s.signs && s.twoFactorMethodConfigured(iam.TwoFactorTOTP) && len(s.totpKey) == 0 {
		s.log.Warn("authkit: TOTP is offered but Deps.KeySource holds no TOTP key (totp.key beside keys.json), so it is unavailable")
	}
	if err := s.initRiver(ctx, deps.Postgres); err != nil {
		return nil, err
	}
	if err := s.initProvisioning(ctx); err != nil {
		return nil, err
	}
	if err := s.initializeGroups(ctx); err != nil {
		return nil, err
	}
	// Cache the root group's id: token mints read root roles through the
	// caller's transaction and never resolve it themselves.
	if s.pg != nil {
		if _, err := s.rootGroup(ctx, s.groupStore()); err != nil {
			return nil, err
		}
	}
	if err := s.reconcileRoleCatalog(ctx); err != nil {
		return nil, err
	}
	if err := s.reconcileRemoteApplications(ctx); err != nil {
		return nil, err
	}
	if s.auth, err = s.newAuthenticator([]string{s.cfg.Issuer}, true); err != nil {
		return nil, err
	}
	if s.cfg.Resource.Enabled() {
		if s.resource, err = s.newResourceServer(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// migrateDirect runs migrate on a pool that reaches PostgreSQL directly: the
// migrators hold session locks. Behind a pooler that is a pool of its own,
// dialed from Deps.PostgresSession and closed after.
func migrateDirect(ctx context.Context, deps config.Deps, migrate func(*pgxpool.Pool) error) error {
	if deps.PostgresSession == nil {
		return migrate(deps.Postgres)
	}
	direct, err := pgxpool.NewWithConfig(ctx, deps.PostgresSession.Copy())
	if err != nil {
		return fmt.Errorf("authkit: migration session: %w", err)
	}
	defer direct.Close()
	return migrate(direct)
}

// postgresBootWait bounds how long New waits for PostgreSQL to answer when
// ctx sets no earlier deadline.
const postgresBootWait = 30 * time.Second

// waitForPostgres pings pool with backoff until it answers, ctx ends or
// postgresBootWait passes: a database restarting beside AuthKit is waited
// for, one that stays down fails the boot.
func waitForPostgres(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(ctx, postgresBootWait)
	defer cancel()
	start, wait := time.Now(), 250*time.Millisecond
	for attempt := 1; ; attempt++ {
		pingCtx, done := context.WithTimeout(ctx, 5*time.Second)
		err := pool.Ping(pingCtx)
		done()
		if err == nil {
			if attempt > 1 {
				log.Info("authkit: PostgreSQL answers", "attempts", attempt)
			}
			return nil
		}
		log.Warn("authkit: PostgreSQL does not answer; retrying", "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return fmt.Errorf("authkit: PostgreSQL unreachable after %d attempts over %s: %w", attempt, time.Since(start).Round(time.Millisecond), err)
		case <-time.After(wait):
		}
		wait = min(2*wait, 4*time.Second)
	}
}

// engineKeySource is the host's Deps.KeySource, else keys.Watch of the key
// directory (/vault/auth, or a loopback issuer's development directory).
// With no keys a loopback issuer generates development keys and any other
// fails construction; development keys sign only for a loopback issuer. The
// source is read per operation, never snapshotted, so a hot-reloading file
// source is observed for the engine's lifetime (#238). owned is closed with
// the engine.
func engineKeySource(host keys.Source, dev *developmentKeys, log *slog.Logger) (_ keys.Source, owned *keys.FileSource, _ error) {
	switch {
	case host != nil:
		if marked, ok := host.(interface{ Development() bool }); ok && marked.Development() {
			if err := dev.refuse("Deps.KeySource"); err != nil {
				return nil, nil, err
			}
			dev.used = true
		}
		return host, nil, nil
	}
	src, err := signingKeys(dev, log)
	if err != nil {
		return nil, nil, err
	}
	return src, src, nil
}

// Config is the normalized configuration the engine runs with.
func (s *Engine) Config() config.Config { return s.cfg }

func (s *Engine) registrationVerificationRequired() bool {
	return true
}

func (s *Engine) RegistrationVerificationEnabled() bool {
	return true
}

// PublicNativeUserRegistrationEnabled reports whether public native-user
// self-registration / auto-registration is allowed.
func (s *Engine) PublicNativeUserRegistrationEnabled() bool {
	return s.cfg.Registration == iam.RegistrationModeOpen
}

// requireMFAEnrollment reports whether every user must enroll a second factor
// before establishing/refreshing a session (TwoFactor.Mode == "required").
func (s *Engine) requireMFAEnrollment() bool {
	return s.cfg.TwoFactor == iam.TwoFactorRequired
}
