package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/keys"
)

// New builds the engine: it normalizes cfg once (config.Normalize), resolves
// keys, waits for PostgreSQL (waitForPostgres), creates or upgrades the tables
// (Migrate), then builds the store, River, the permission groups and the
// request authenticator. ctx bounds the boot-time database work. It fails
// only on what AuthKit cannot run safely with; a survivable problem switches
// off the feature it concerns and is reported by Probes.
func New(ctx context.Context, cfg config.Config, deps config.Deps) (_ *Engine, err error) {
	norm, degraded, err := config.Normalize(cfg, deps)
	if err != nil {
		return nil, err
	}
	gs, err := config.CompileRoles(norm.Roles)
	if err != nil {
		return nil, err
	}
	// #232: the TOTP key is the explicit override or <Keys.Path>/totp.key;
	// without either, TOTP is unavailable. The engine reads Config, so the
	// resolved key is written back into it.
	if norm.TwoFactor.TOTPSecretKey, err = resolveTOTPSecretKey(norm); err != nil {
		return nil, err
	}
	src, owned, err := engineKeySource(norm.Keys, deps.KeySource)
	if err != nil {
		return nil, err
	}
	s := &Engine{
		cfg:               norm,
		keys:              src,
		ownedKeySource:    owned,
		signs:             deps.KeySource != nil || !norm.Keys.VerifyOnly,
		schema:            norm.Database.Schema,
		groupSchema:       gs,
		solanaSNSResolver: newDefaultSolanaSNSResolver(),
		now:               time.Now,
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
		if err := waitForPostgres(ctx, deps.Postgres); err != nil {
			return nil, err
		}
		if err := Migrate(ctx, deps.Postgres, norm.Database); err != nil {
			return nil, err
		}
	}
	if err := s.applyDeps(deps); err != nil {
		return nil, err
	}
	if problem := s.secondFactorProblem(); problem != nil {
		s.degrade(problem)
	} else if s.signs && s.twoFactorMethodConfigured(iam.TwoFactorTOTP) && len(s.cfg.TwoFactor.TOTPSecretKey) == 0 {
		slog.Warn("authkit: TOTP is offered but has no key, so it is unavailable", "path", filepath.Join(totpKeysDir(s.cfg), totpKeyFilename))
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
	if s.auth, err = s.newAuthenticator(s.cfg.Token.ExpectedAudiences, true); err != nil {
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
func waitForPostgres(ctx context.Context, pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(ctx, postgresBootWait)
	defer cancel()
	start, wait := time.Now(), 250*time.Millisecond
	for attempt := 1; ; attempt++ {
		pingCtx, done := context.WithTimeout(ctx, 5*time.Second)
		err := pool.Ping(pingCtx)
		done()
		if err == nil {
			if attempt > 1 {
				slog.Info("authkit: PostgreSQL answers", "attempts", attempt)
			}
			return nil
		}
		slog.Warn("authkit: PostgreSQL does not answer; retrying", "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return fmt.Errorf("authkit: PostgreSQL unreachable after %d attempts over %s: %w", attempt, time.Since(start).Round(time.Millisecond), err)
		case <-time.After(wait):
		}
		wait = min(2*wait, 4*time.Second)
	}
}

// engineKeySource is the host's Deps.KeySource, or none (VerifyOnly), or
// <Keys.Path>/keys.json. No environment variables are read (#231); with no
// keys and no AllowEphemeralDevKeys opt-in, construction fails. The source is
// read per operation, never snapshotted, so a hot-reloading file source is
// observed for the engine's lifetime (#238). owned is closed with the engine.
func engineKeySource(c config.KeysConfig, host keys.Source) (_ keys.Source, owned *keys.FileSource, _ error) {
	switch {
	case host != nil:
		return host, nil, nil
	case c.VerifyOnly:
		// #87: no signer: minting returns ErrSigningNotConfigured, while
		// verification, permission reads and the (empty) JWKS work.
		return keys.Static{}, nil, nil
	}
	src, err := resolveKeySource(c.Path, c.AllowEphemeralDevKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("authkit: failed to resolve JWT signing keys (set Keys.Path to a directory containing keys.json, provide Deps.KeySource, or — for development only — set Keys.AllowEphemeralDevKeys): %w", err)
	}
	owned, _ = src.(*keys.FileSource)
	return src, owned, nil
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
