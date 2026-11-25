package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	notifypg "github.com/open-rails/authkit/notify/postgres"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
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
	dev, err := newDevelopmentKeys(norm.Keys, norm.Issuer)
	if err != nil {
		return nil, err
	}
	norm.Keys.Path = dev.dir
	signs := deps.KeySource != nil || !norm.Keys.VerifyOnly
	// #232: the TOTP key is the explicit override or <Keys.Path>/totp.key;
	// without either, TOTP is unavailable. The engine reads Config, so the
	// resolved key is written back into it.
	if norm.TwoFactor.TOTPSecretKey, err = resolveTOTPSecretKey(norm, signs, dev, log); err != nil {
		return nil, err
	}
	src, owned, err := engineKeySource(norm.Keys, deps.KeySource, dev, log)
	if err != nil {
		return nil, err
	}
	dev.report(log)
	s := &Engine{
		log:               log,
		cfg:               norm,
		passkeys:          config.Passkeys(norm.FrontendURL),
		keys:              src,
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
	if !norm.Keys.VerifyOnly && src.ActiveSigner() == nil {
		return nil, errors.New("authkit: Deps.KeySource has no active signing key, so no token could be signed; give it one, or set Keys.VerifyOnly for a deployment that only verifies")
	}
	for _, problem := range degraded {
		s.degrade(problem)
	}
	if deps.Postgres != nil {
		if err := waitForPostgres(ctx, log, deps.Postgres); err != nil {
			return nil, err
		}
		if norm.Database.SkipMigrations {
			if err := validateMigrations(ctx, log, deps.Postgres, norm.Database); err != nil {
				return nil, err
			}
		} else {
			if err := Migrate(ctx, deps.Postgres, norm.Database, MigrationOptions{Tenancy: norm.Tenancy, LegacyTenantID: norm.DefaultTenantID, Logger: log}); err != nil {
				return nil, err
			}
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
	if norm.Notifications != nil {
		if norm.Database.SkipMigrations {
			if err := notifypg.Validate(ctx, deps.Postgres, norm.Notifications.Schema); err != nil {
				return nil, err
			}
			if err := notificationBindingMigrations(ctx, log, deps.Postgres, norm.Notifications.Schema, true); err != nil {
				return nil, err
			}
			if err := notificationConfiguredBindings(ctx, deps.Postgres, norm.Database, norm.Notifications, norm.DefaultTenantID, false); err != nil {
				return nil, err
			}
		} else if err := MigrateNotifications(ctx, log, deps.Postgres, norm.Database, norm.Notifications, norm.DefaultTenantID); err != nil {
			return nil, err
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
	} else if s.signs && s.twoFactorMethodConfigured(iam.TwoFactorTOTP) && len(s.cfg.TwoFactor.TOTPSecretKey) == 0 {
		s.log.Warn("authkit: TOTP is offered but has no key, so it is unavailable", "path", filepath.Join(s.cfg.Keys.Path, totpKeyFilename))
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

// engineKeySource is the host's Deps.KeySource, or none (VerifyOnly), or
// <Keys.Path>/keys.json. With no keys a loopback issuer generates development
// keys and any other fails construction; development keys sign only for a
// loopback issuer. The source is read per operation, never snapshotted, so a
// hot-reloading file source is observed for the engine's lifetime (#238).
// owned is closed with the engine.
func engineKeySource(c config.KeysConfig, host keys.Source, dev *developmentKeys, log *slog.Logger) (_ keys.Source, owned *keys.FileSource, _ error) {
	switch {
	case host != nil:
		if marked, ok := host.(interface{ Development() bool }); ok && marked.Development() {
			if err := dev.refuse("Deps.KeySource"); err != nil {
				return nil, nil, err
			}
		}
		return host, nil, nil
	case c.VerifyOnly:
		// #87: no signer: minting returns ErrSigningNotConfigured, while
		// verification, permission reads and the (empty) JWKS work.
		return keys.Static{}, nil, nil
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
	return s.cfg.Registration.Verification == iam.RegistrationVerificationRequired
}

func (s *Engine) RegistrationVerificationEnabled() bool {
	return s.cfg.Registration.Verification != iam.RegistrationVerificationNone
}

// PublicNativeUserRegistrationEnabled reports whether public native-user
// self-registration / auto-registration is allowed.
func (s *Engine) PublicNativeUserRegistrationEnabled() bool {
	return s.cfg.Registration.NativeUserMode == iam.RegistrationModeOpen
}

// requireMFAEnrollment reports whether every user must enroll a second factor
// before establishing/refreshing a session (TwoFactor.Mode == "required").
func (s *Engine) requireMFAEnrollment() bool {
	return s.cfg.TwoFactor.Mode == iam.TwoFactorRequired
}
