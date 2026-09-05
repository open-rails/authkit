package embedded

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

func (s *Client) namingNow() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func lockNameClaims(ctx context.Context, q db.DBTX, kind, persona string, names ...string) error {
	_, err := q.Exec(ctx, `SELECT profiles.lock_name_claims($1,$2,$3::text[])`, kind, persona, names)
	return err
}

func claimCanonicalName(ctx context.Context, q db.DBTX, kind, persona, name, id string, now time.Time) error {
	_, err := q.Exec(ctx, `SELECT profiles.claim_canonical_name($1, $2, $3, $4::uuid, $5)`, kind, persona, name, id, now)
	return nameClaimError(err, kind)
}

func nameClaimError(err error, kind string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "name_claims_pkey" {
		if kind == "group" {
			return ErrGroupSlugTaken
		}
		return mapUserUniqueViolation(err)
	}
	return err
}

// renameNameClaim requires the owner row locked by its caller. Name locks are
// sorted by stripe before either claim changes, so opposite renames do not deadlock.
func renameNameClaim(ctx context.Context, q db.DBTX, kind, persona, id, oldName, newName string, now time.Time, policy authkit.NamingPolicy) error {
	if err := lockNameClaims(ctx, q, kind, persona, oldName, newName); err != nil {
		return err
	}
	if oldName != "" {
		if policy.FormerNameRetentionMode == authkit.FormerNamesImmediate {
			if _, err := q.Exec(ctx, `DELETE FROM profiles.name_claims WHERE owner_kind=$1 AND persona=$2 AND name=lower($3) AND owner_id=$4::uuid AND canonical`, kind, persona, oldName, id); err != nil {
				return err
			}
		} else {
			if _, err := q.Exec(ctx, `UPDATE profiles.name_claims SET canonical=false, expires_at=$5 WHERE owner_kind=$1 AND persona=$2 AND name=lower($3) AND owner_id=$4::uuid AND canonical`, kind, persona, oldName, id, policy.FormerNameExpiresAt(now)); err != nil {
				return err
			}
		}
	}
	return claimCanonicalName(ctx, q, kind, persona, newName, id, now)
}

// ResolveUsername resolves current names and unexpired aliases directly to UUID.
func (s *Client) ResolveUsername(ctx context.Context, name string) (authkit.NameResolution, error) {
	if err := s.requirePG(); err != nil {
		return authkit.NameResolution{}, err
	}
	row, err := s.q.ResolveUsername(ctx, db.ResolveUsernameParams{Name: strings.TrimSpace(name), AtTime: s.namingNow()})
	return authkit.NameResolution{ID: row.ID, CanonicalName: row.CanonicalName, IsAlias: row.IsAlias, AliasExpiresAt: row.ExpiresAt}, err
}

func (s *Client) admitName(ctx context.Context, request authkit.NameAdmissionRequest) error {
	if s.nameAdmission == nil {
		return nil
	}
	if err := s.nameAdmission(ctx, request); err != nil {
		return fmt.Errorf("%w: %w", authkit.ErrNameAdmissionRefused, err)
	}
	return nil
}
func (s *Client) UserNamingState(ctx context.Context, id string) (authkit.NamingState, error) {
	if err := s.requirePG(); err != nil {
		return authkit.NamingState{}, err
	}
	var last *time.Time
	err := db.ForSchema(s.pg, s.dbSchema()).QueryRow(ctx, `SELECT last_renamed_at FROM profiles.users WHERE id=$1::uuid AND deleted_at IS NULL`, id).Scan(&last)
	if err != nil {
		return authkit.NamingState{}, err
	}
	return s.namingStateWithAliases(ctx, "user", id, last)
}
func (s *Client) GroupNamingState(ctx context.Context, id string) (authkit.NamingState, error) {
	if err := s.requirePG(); err != nil {
		return authkit.NamingState{}, err
	}
	var last *time.Time
	err := db.ForSchema(s.pg, s.dbSchema()).QueryRow(ctx, `SELECT last_renamed_at FROM profiles.permission_groups WHERE id=$1::uuid`, id).Scan(&last)
	if err != nil {
		return authkit.NamingState{}, err
	}
	return s.namingStateWithAliases(ctx, "group", id, last)
}

func (s *Client) namingStateWithAliases(ctx context.Context, kind, id string, last *time.Time) (authkit.NamingState, error) {
	now := s.namingNow()
	state := s.NamingPolicy().State(last, now)
	rows, err := db.ForSchema(s.pg, s.dbSchema()).Query(ctx, `SELECT name,expires_at FROM profiles.name_claims WHERE owner_kind=$1 AND owner_id=$2::uuid AND NOT canonical AND (expires_at IS NULL OR expires_at>$3) ORDER BY name`, kind, id, now)
	if err != nil {
		return state, err
	}
	defer rows.Close()
	for rows.Next() {
		var alias authkit.NameAlias
		if err := rows.Scan(&alias.Name, &alias.ExpiresAt); err != nil {
			return state, err
		}
		state.Aliases = append(state.Aliases, alias)
	}
	return state, rows.Err()
}
