package authcore

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

func (s *Service) namingNow() time.Time {
	if s.namingClock != nil {
		return s.namingClock().UTC()
	}
	return time.Now().UTC()
}

func lockNameClaims(ctx context.Context, q db.DBTX, kind, persona string, names ...string) error {
	names = append([]string(nil), names...)
	for i := range names {
		names[i] = strings.ToLower(names[i])
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, err := q.Exec(ctx, `SELECT profiles.lock_name_claim($1, $2, $3)`, kind, persona, name); err != nil {
			return err
		}
	}
	return nil
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
		return authkit.ErrOwnerSlugTaken
	}
	return err
}

// renameNameClaim requires the owner row locked by its caller. Name locks are
// sorted before either claim changes, so opposite renames cannot deadlock.
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
func (s *Service) ResolveUsername(ctx context.Context, name string) (authkit.NameResolution, error) {
	row, err := s.q.ResolveUsername(ctx, db.ResolveUsernameParams{Name: strings.TrimSpace(name), AtTime: s.namingNow()})
	return authkit.NameResolution{ID: row.ID, CanonicalName: row.CanonicalName, IsAlias: row.IsAlias, AliasExpiresAt: row.ExpiresAt}, err
}

func (s *Service) admitName(ctx context.Context, request authkit.NameAdmissionRequest) error {
	if s.nameAdmission == nil {
		return nil
	}
	if err := s.nameAdmission(ctx, request); err != nil {
		return fmt.Errorf("%w: %w", authkit.ErrNameAdmissionRefused, err)
	}
	return nil
}
func (s *Service) UserNamingState(ctx context.Context, id string) (authkit.NamingState, error) {
	var last *time.Time
	err := db.ForSchema(s.pg, s.dbSchema()).QueryRow(ctx, `SELECT last_renamed_at FROM profiles.users WHERE id=$1::uuid AND deleted_at IS NULL`, id).Scan(&last)
	return s.NamingPolicy().State(last, s.namingNow()), err
}
func (s *Service) GroupNamingState(ctx context.Context, id string) (authkit.NamingState, error) {
	var last *time.Time
	err := db.ForSchema(s.pg, s.dbSchema()).QueryRow(ctx, `SELECT last_renamed_at FROM profiles.permission_groups WHERE id=$1::uuid`, id).Scan(&last)
	return s.NamingPolicy().State(last, s.namingNow()), err
}
