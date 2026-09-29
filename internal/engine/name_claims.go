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
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
)

func (s *Engine) namingNow() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// Name claims hold usernames and their former-name aliases.

func lockNameClaims(ctx context.Context, q db.DBTX, names ...string) error {
	_, err := q.Exec(ctx, `SELECT lock_name_claims('user','',$1::text[])`, names)
	return err
}

func claimCanonicalName(ctx context.Context, q db.DBTX, name, id string, now time.Time) error {
	_, err := q.Exec(ctx, `SELECT claim_canonical_name('user', '', $1, $2::uuid, $3)`, name, id, now)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "name_claims_pkey" {
		return mapUserUniqueViolation(err)
	}
	return err
}

// renameNameClaim requires the account row locked by its caller. Name locks
// are sorted by stripe before either claim changes, so opposite renames do not
// deadlock.
func renameNameClaim(ctx context.Context, q db.DBTX, id, oldName, newName string, now time.Time, policy iam.NamingPolicy) error {
	if err := lockNameClaims(ctx, q, oldName, newName); err != nil {
		return err
	}
	if oldName != "" {
		if policy.FormerNameRetentionMode == iam.FormerNamesImmediate {
			if _, err := q.Exec(ctx, `DELETE FROM name_claims WHERE owner_kind='user' AND persona='' AND name=lower($1) AND owner_id=$2::uuid AND canonical`, oldName, id); err != nil {
				return err
			}
		} else {
			if _, err := q.Exec(ctx, `UPDATE name_claims SET canonical=false, expires_at=$3 WHERE owner_kind='user' AND persona='' AND name=lower($1) AND owner_id=$2::uuid AND canonical`, oldName, id, policy.FormerNameExpiresAt(now)); err != nil {
				return err
			}
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
	if err := s.cfg.Username.Validate(name); err != nil {
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
	return s.admitName(ctx, iam.NameAdmissionRequest{OwnerKind: "user", RequestedName: name, Operation: iam.NameCreate})
}

// usernameTaken reports whether any claim holds name: a canonical name, an
// unexpired alias, or a purged account's permanent reservation.
func (s *Engine) usernameTaken(ctx context.Context, name string) (bool, error) {
	var taken bool
	err := s.pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM name_claims WHERE owner_kind='user' AND persona='' AND name=lower($1) AND (canonical OR expires_at IS NULL OR expires_at>$2))`, strings.TrimSpace(name), s.namingNow()).Scan(&taken)
	return taken, err
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
func (s *Engine) UserNamingState(ctx context.Context, id string) (iam.NamingState, error) {
	if err := s.requirePG(); err != nil {
		return iam.NamingState{}, err
	}
	var last *time.Time
	err := s.pg.QueryRow(ctx, `SELECT last_renamed_at FROM users WHERE id=$1::uuid AND deleted_at IS NULL`, id).Scan(&last)
	if err != nil {
		return iam.NamingState{}, err
	}
	now := s.namingNow()
	state := s.NamingPolicy().State(last, now)
	rows, err := s.pg.Query(ctx, `SELECT name,expires_at FROM name_claims WHERE owner_kind='user' AND owner_id=$1::uuid AND NOT canonical AND (expires_at IS NULL OR expires_at>$2) ORDER BY name`, id, now)
	if err != nil {
		return state, err
	}
	defer rows.Close()
	for rows.Next() {
		var alias iam.NameAlias
		if err := rows.Scan(&alias.Name, &alias.ExpiresAt); err != nil {
			return state, err
		}
		state.Aliases = append(state.Aliases, alias)
	}
	return state, rows.Err()
}
