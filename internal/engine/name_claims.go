package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/naming"
)

func (s *Engine) namingNow() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// Name claims hold usernames and their former-name aliases.

func (s *Engine) lockNameClaims(ctx context.Context, q db.DBTX, names ...string) error {
	return db.New(q).NameClaimsLock(ctx, db.NameClaimsLockParams{TenantID: s.tenantKey(ctx), Names: names})
}

func (s *Engine) claimCanonicalName(ctx context.Context, q db.DBTX, name, id string, now time.Time) error {
	err := db.New(q).NameClaimCanonical(ctx, db.NameClaimCanonicalParams{TenantID: s.tenantKey(ctx), Name: name, OwnerID: id, AtTime: now})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "name_claims_pkey" {
		return mapUserUniqueViolation(err)
	}
	return err
}

// renameNameClaim requires the account row locked by its caller. Name locks
// are sorted by stripe before either claim changes, so opposite renames do not
// deadlock.
func (s *Engine) renameNameClaim(ctx context.Context, q db.DBTX, id, oldName, newName string, now time.Time, policy config.UsernameConfig) error {
	if err := s.lockNameClaims(ctx, q, oldName, newName); err != nil {
		return err
	}
	if err := s.retireNameClaim(ctx, q, id, oldName, policy.FormerNames, now); err != nil {
		return err
	}
	return s.claimCanonicalName(ctx, q, newName, id, now)
}

// releaseDeletedName applies Username.DeletedNames to the canonical name of an
// account being purged, whose row its caller holds locked.
func (s *Engine) releaseDeletedName(ctx context.Context, q db.DBTX, id, name string) error {
	if err := s.lockNameClaims(ctx, q, name); err != nil {
		return err
	}
	return s.retireNameClaim(ctx, q, id, name, s.cfg.Username.DeletedNames, s.namingNow())
}

// retireNameClaim makes id's canonical name a reservation that lasts as
// retention says, or frees it when immediate. The caller holds its lock.
func (s *Engine) retireNameClaim(ctx context.Context, q db.DBTX, id, name string, retention config.NameRetention, now time.Time) error {
	if name == "" {
		return nil
	}
	if retention.Mode == config.NameRetentionImmediate {
		return db.New(q).NameClaimDeleteOwned(ctx, db.NameClaimDeleteOwnedParams{TenantID: s.tenantKey(ctx), Name: name, OwnerID: id})
	}
	return db.New(q).NameClaimRetire(ctx, db.NameClaimRetireParams{TenantID: s.tenantKey(ctx), Name: name, OwnerID: id, ExpiresAt: naming.ExpiresAt(retention, now)})
}

// resolveUsername resolves current names and unexpired aliases directly to UUID.
func (s *Engine) resolveUsername(ctx context.Context, name string) (iam.NameResolution, error) {
	if err := s.requirePG(); err != nil {
		return iam.NameResolution{}, err
	}
	row, err := s.q.ResolveUsername(ctx, db.ResolveUsernameParams{TenantID: s.tenantKey(ctx), Name: strings.TrimSpace(name), AtTime: s.namingNow()})
	return iam.NameResolution{ID: row.ID, CanonicalName: naming.Canonical(row.CanonicalName), IsAlias: row.IsAlias, AliasExpiresAt: row.ExpiresAt}, err
}

// ResolveUsername resolves a current username or live alias of a live account.
func (s *Engine) ResolveUsername(ctx context.Context, name string) (iam.NameResolution, error) {
	r, err := s.resolveUsername(ctx, name)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.NameResolution{}, iam.ErrUserNotFound
	}
	return r, err
}

// CheckUsername reports whether a new account could take name: the username
// policy, then any claim on it (a canonical name, a live alias, an unexpired
// purged account's reservation, a pending registration), then NameAdmission.
// A claim answers ErrUsernameInUse and nothing about its owner.
func (s *Engine) CheckUsername(ctx context.Context, name string) error {
	return s.checkUsername(ctx, s.q, name)
}

func (s *Engine) checkUsername(ctx context.Context, q *db.Queries, name string) error {
	name = naming.Canonical(name)
	if err := naming.Validate(s.cfg.Username, name); err != nil {
		return err
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	taken, err := q.NameClaimTaken(ctx, db.NameClaimTakenParams{TenantID: s.tenantKey(ctx), Name: name, AtTime: s.namingNow()})
	if err != nil {
		return err
	}
	if taken || s.pendingChangeUsernameTaken(ctx, name) {
		return iam.ErrUsernameInUse
	}
	return s.admitName(ctx, iam.NameAdmissionRequest{RequestedName: name, Operation: iam.NameCreate})
}

// usernameTaken reports whether any claim holds name: a canonical name, an
// unexpired alias, or an unexpired purged account's reservation.
func (s *Engine) usernameTaken(ctx context.Context, name string) (bool, error) {
	return s.q.NameClaimTaken(ctx, db.NameClaimTakenParams{TenantID: s.tenantKey(ctx), Name: strings.TrimSpace(name), AtTime: s.namingNow()})
}

func (s *Engine) admitName(ctx context.Context, request iam.NameAdmissionRequest) error {
	if s.nameAdmission == nil {
		return nil
	}
	if err := s.nameAdmission(ctx, request); err != nil {
		return fmt.Errorf("%w: %w", errmodel.ErrNameAdmissionRefused, err)
	}
	return nil
}
func (s *Engine) UserNamingState(ctx context.Context, id string) (naming.State, error) {
	if err := s.requirePG(); err != nil {
		return naming.State{}, err
	}
	last, err := s.q.UserLastRenamedAt(ctx, id)
	if err != nil {
		return naming.State{}, err
	}
	now := s.namingNow()
	state := naming.NewState(s.cfg.Username, last, now)
	aliases, err := s.q.NameClaimAliasesByUser(ctx, db.NameClaimAliasesByUserParams{TenantID: s.tenantKey(ctx), OwnerID: id, AtTime: now})
	if err != nil {
		return state, err
	}
	for _, a := range aliases {
		state.Aliases = append(state.Aliases, naming.Alias{Name: naming.Canonical(a.Name), ExpiresAt: a.ExpiresAt})
	}
	return state, nil
}
