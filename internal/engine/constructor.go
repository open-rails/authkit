package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/keys"
)

// New builds the engine: it normalizes cfg once (config.Normalize), resolves
// keys, then builds the store, River, the permission groups and the request
// authenticator. ctx bounds the boot-time database work.
func New(ctx context.Context, cfg config.Config, deps config.Deps) (_ *Engine, err error) {
	norm, err := config.Normalize(cfg, deps)
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
		schema:            norm.Schema,
		groupSchema:       gs,
		solanaSNSResolver: newDefaultSolanaSNSResolver(),
		now:               time.Now,
	}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	if err := s.applyDeps(deps); err != nil {
		return nil, err
	}
	if err := s.requireEnrollableSecondFactor(deps.KeySource != nil || !norm.Keys.VerifyOnly); err != nil {
		return nil, err
	}
	if err := s.probeMigrations(); err != nil {
		return nil, err
	}
	if err := s.initRiver(deps.Postgres); err != nil {
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
	return s, nil
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
