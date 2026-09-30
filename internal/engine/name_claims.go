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

func lockNameClaims(ctx context.Context, q db.DBTX, names ...string) error {
	return db.New(q).NameClaimsLock(ctx, names)
}

func claimCanonicalName(ctx context.Context, q db.DBTX, name, id string, now time.Time) error {
	err := db.New(q).NameClaimCanonical(ctx, db.NameClaimCanonicalParams{Name: name, OwnerID: id, AtTime: now})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "name_claims_pkey" {
		return mapUserUniqueViolation(err)
	}
	return err
}

// renameNameClaim requires the account row locked by its caller. Name locks
// are sorted by stripe before either claim changes, so opposite renames do not
// deadlock.
func renameNameClaim(ctx context.Context, q db.DBTX, id, oldName, newName string, now time.Time, policy config.UsernameConfig) error {
	if err := lockNameClaims(ctx, q, oldName, newName); err != nil {
		return err
	}
	if oldName != "" {
		queries := db.New(q)
		var err error
		if policy.FormerNames.Mode == config.FormerNamesImmediate {
			err = queries.NameClaimDeleteOwned(ctx, db.NameClaimDeleteOwnedParams{Name: oldName, OwnerID: id})
		} else {
			err = queries.NameClaimRetire(ctx, db.NameClaimRetireParams{Name: oldName, OwnerID: id, ExpiresAt: naming.FormerNameExpiresAt(policy, now)})
		}
		if err != nil {
			return err
		}
	}
	return claimCanonicalName(ctx, q, newName, id, now)
}

// resolveUsername resolves current names and unexpired aliases directly to UUID.
func (s *Engine) resolveUsername(ctx context.Context, name string) (iam.NameResolution, error) {
	if err := s.requirePG(); err != nil {
		return iam.NameResolution{}, err
	}
	row, err := s.q.ResolveUsername(ctx, db.ResolveUsernameParams{Name: strings.TrimSpace(name), AtTime: s.namingNow()})
	return iam.NameResolution{ID: row.ID, CanonicalName: row.CanonicalName, IsAlias: row.IsAlias, AliasExpiresAt: row.ExpiresAt}, err
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
// policy, then any claim on it (a canonical name, a live alias, a purged
// account's reservation, a pending registration), then NameAdmission. A claim
// answers ErrUsernameInUse and nothing about its owner.
func (s *Engine) CheckUsername(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if err := naming.Validate(s.cfg.Username, name); err != nil {
		return err
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	taken, err := s.usernameTaken(ctx, name)
	if err != nil {
		return err
	}
	if taken || s.pendingChangeUsernameTaken(ctx, name) {
		return iam.ErrUsernameInUse
	}
	return s.admitName(ctx, iam.NameAdmissionRequest{RequestedName: name, Operation: iam.NameCreate})
}

// usernameTaken reports whether any claim holds name: a canonical name, an
// unexpired alias, or a purged account's permanent reservation.
func (s *Engine) usernameTaken(ctx context.Context, name string) (bool, error) {
	return s.q.NameClaimTaken(ctx, db.NameClaimTakenParams{Name: strings.TrimSpace(name), AtTime: s.namingNow()})
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
	aliases, err := s.q.NameClaimAliasesByUser(ctx, db.NameClaimAliasesByUserParams{OwnerID: id, AtTime: now})
	if err != nil {
		return state, err
	}
	for _, a := range aliases {
		state.Aliases = append(state.Aliases, naming.Alias{Name: a.Name, ExpiresAt: a.ExpiresAt})
	}
	return state, nil
}
