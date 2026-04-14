package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	pwhash "github.com/open-rails/authkit/password"
)

var (
	ErrReservedAccountNotFound  = errors.New("reserved_account_not_found")
	ErrReservedAccountClaimed   = errors.New("reserved_account_claimed")
	ErrReservedAccountProtected = errors.New("reserved_account_protected")
)

func normalizeReservedSlug(slug string) string {
	return strings.ToLower(strings.TrimSpace(slug))
}

func (s *Service) reservedUserFlagExpr() string {
	return `CASE
		WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
		THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
		ELSE false
	END`
}

func (s *Service) setUserReservedTx(ctx context.Context, tx pgx.Tx, userID string, reserved bool) error {
	if tx == nil {
		return fmt.Errorf("tx required")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	_, err := tx.Exec(ctx, `
		UPDATE profiles.users
		SET metadata=jsonb_set(COALESCE(metadata, '{}'::jsonb), '{reserved}', to_jsonb($2::boolean), true),
			updated_at=now()
		WHERE id=$1::uuid
	`, userID, reserved)
	return err
}

func (s *Service) setOrgReservedTx(ctx context.Context, tx pgx.Tx, orgID string, reserved bool) error {
	if tx == nil {
		return fmt.Errorf("tx required")
	}
	if strings.TrimSpace(orgID) == "" {
		return fmt.Errorf("invalid_org")
	}
	_, err := tx.Exec(ctx, `
		UPDATE profiles.orgs
		SET metadata=jsonb_set(COALESCE(metadata, '{}'::jsonb), '{reserved}', to_jsonb($2::boolean), true),
			updated_at=now()
		WHERE id=$1::uuid
	`, orgID, reserved)
	return err
}

// enforceReservedPlaceholderCredentialInvariantTx ensures reserved placeholders
// remain non-loginable by clearing direct credentials and provider links.
func (s *Service) enforceReservedPlaceholderCredentialInvariantTx(ctx context.Context, tx pgx.Tx, userID string) error {
	if tx == nil {
		return fmt.Errorf("tx required")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	if _, err := tx.Exec(ctx, `DELETE FROM profiles.user_passwords WHERE user_id=$1::uuid`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM profiles.user_providers WHERE user_id=$1::uuid`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE profiles.users
		SET email=NULL,
			email_verified=false,
			phone_number=NULL,
			phone_verified=false,
			updated_at=now()
		WHERE id=$1::uuid
	`, userID); err != nil {
		return err
	}
	return nil
}

func (s *Service) GetUserMetadata(ctx context.Context, userID string) (map[string]any, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	var raw []byte
	if err := s.pg.QueryRow(ctx, `SELECT COALESCE(metadata, '{}'::jsonb) FROM profiles.users WHERE id=$1::uuid`, userID).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) PatchUserMetadata(ctx context.Context, userID string, patch map[string]any) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	if len(patch) == 0 {
		return nil
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	tag, err := s.pg.Exec(ctx, `
		UPDATE profiles.users
		SET metadata=COALESCE(metadata, '{}'::jsonb) || $2::jsonb,
			updated_at=now()
		WHERE id=$1::uuid
	`, userID, raw)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *Service) GetOrgMetadata(ctx context.Context, orgID string) (map[string]any, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(orgID) == "" {
		return nil, fmt.Errorf("invalid_org")
	}
	var raw []byte
	if err := s.pg.QueryRow(ctx, `SELECT COALESCE(metadata, '{}'::jsonb) FROM profiles.orgs WHERE id=$1::uuid AND deleted_at IS NULL`, orgID).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOrgNotFound
		}
		return nil, err
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) PatchOrgMetadata(ctx context.Context, orgID string, patch map[string]any) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if strings.TrimSpace(orgID) == "" {
		return fmt.Errorf("invalid_org")
	}
	if len(patch) == 0 {
		return nil
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	tag, err := s.pg.Exec(ctx, `
		UPDATE profiles.orgs
		SET metadata=COALESCE(metadata, '{}'::jsonb) || $2::jsonb,
			updated_at=now()
		WHERE id=$1::uuid AND deleted_at IS NULL
	`, orgID, raw)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrOrgNotFound
	}
	return nil
}

func (s *Service) IsOrgReserved(ctx context.Context, orgID string) (bool, error) {
	state, err := s.GetOrgNamespaceState(ctx, orgID)
	if err != nil {
		return false, err
	}
	return state == OwnerNamespaceStateParkedOrg, nil
}

func (s *Service) IsOrgReservedBySlug(ctx context.Context, slug string) (string, bool, error) {
	org, err := s.ResolveOrgBySlug(ctx, normalizeReservedSlug(slug))
	if err != nil {
		return "", false, err
	}
	reserved, err := s.IsOrgReserved(ctx, org.ID)
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(org.ID), reserved, nil
}

// ReserveAccount reserves a namespace slug without requiring a same-slug login user.
// For legacy placeholder rows, it still enforces non-loginable reserved invariants.
func (s *Service) ReserveAccount(ctx context.Context, slug string) (userID, orgID string, reserved bool, err error) {
	if err := s.requirePG(); err != nil {
		return "", "", false, err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateOrgSlug(slug); err != nil {
		return "", "", false, err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", "", false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		existingOrgID       string
		existingOrgReserved bool
	)
	if err := tx.QueryRow(ctx, `
		SELECT id::text,
		       CASE
		         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
		         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
		         ELSE false
		       END
		FROM profiles.orgs
		WHERE slug=$1
		  AND deleted_at IS NULL
	`, slug).Scan(&existingOrgID, &existingOrgReserved); err == nil {
		orgID = strings.TrimSpace(existingOrgID)
		if !existingOrgReserved {
			return "", "", false, ErrReservedAccountClaimed
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, err
	}

	var (
		existingUserID   string
		existingReserved bool
	)
	userReservedQuery := `
		SELECT id::text,
		       CASE
		         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
		         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
		         ELSE false
		       END
		FROM profiles.users
		WHERE lower(username::text)=lower($1)
		  AND deleted_at IS NULL
	`
	switch err := tx.QueryRow(ctx, userReservedQuery, slug).Scan(&existingUserID, &existingReserved); {
	case err == nil:
		userID = strings.TrimSpace(existingUserID)
		if !existingReserved {
			return "", "", false, ErrReservedAccountClaimed
		}
	case errors.Is(err, pgx.ErrNoRows):
	default:
		return "", "", false, err
	}

	if strings.TrimSpace(userID) != "" && strings.TrimSpace(orgID) == "" {
		var existingOrgSlug string
		switch err := tx.QueryRow(ctx, `
			SELECT id::text,
			       slug,
			       CASE
			         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
			         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
			         ELSE false
			       END
			FROM profiles.orgs
			WHERE owner_user_id=$1::uuid
			  AND is_personal=true
			  AND deleted_at IS NULL
		`, userID).Scan(&existingOrgID, &existingOrgSlug, &existingOrgReserved); {
		case err == nil:
			orgID = strings.TrimSpace(existingOrgID)
			if !existingOrgReserved {
				return "", "", false, ErrReservedAccountClaimed
			}
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return "", "", false, err
		}
	}

	if strings.TrimSpace(userID) == "" && strings.TrimSpace(orgID) == "" {
		if err := s.ensureOwnerSlugAvailable(ctx, slug, "", ""); err != nil {
			return "", "", false, err
		}
	}

	if err := s.upsertOwnerReservedNameTx(ctx, tx, slug); err != nil {
		return "", "", false, err
	}

	if strings.TrimSpace(userID) != "" {
		if err := s.setUserReservedTx(ctx, tx, userID, true); err != nil {
			return "", "", false, err
		}
		if err := s.enforceReservedPlaceholderCredentialInvariantTx(ctx, tx, userID); err != nil {
			return "", "", false, err
		}
	}

	if strings.TrimSpace(orgID) != "" {
		if err := s.setOrgReservedTx(ctx, tx, orgID, true); err != nil {
			return "", "", false, err
		}
		if err := s.setOrgNamespaceStateTx(ctx, tx, orgID, OwnerNamespaceStateParkedOrg); err != nil {
			return "", "", false, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", "", false, err
	}
	return strings.TrimSpace(userID), strings.TrimSpace(orgID), true, nil
}

// ClaimReservedAccount activates a reserved placeholder account by setting a password,
// optional contact fields, and flipping reserved=false on both user/org metadata.
func (s *Service) ClaimReservedAccount(ctx context.Context, slug, newPassword string, email, phone *string) (userID, orgID string, err error) {
	slug = normalizeReservedSlug(slug)
	if slug == "root" {
		return "", "", ErrReservedAccountProtected
	}
	if err := s.requirePG(); err != nil {
		return "", "", err
	}
	if err := validateOrgSlug(slug); err != nil {
		return "", "", err
	}
	newPassword = strings.TrimSpace(newPassword)
	if err := pwhash.Validate(newPassword); err != nil {
		return "", "", err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userReserved bool
	if err := tx.QueryRow(ctx, `
		SELECT id::text,
		       CASE
		         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
		         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
		         ELSE false
		       END
		FROM profiles.users
		WHERE lower(username::text)=lower($1)
		  AND deleted_at IS NULL
	`, slug).Scan(&userID, &userReserved); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrReservedAccountNotFound
		}
		return "", "", err
	}
	if !userReserved {
		return "", "", ErrReservedAccountClaimed
	}

	var orgReserved bool
	if err := tx.QueryRow(ctx, `
		SELECT id::text,
		       CASE
		         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
		         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
		         ELSE false
		       END
		FROM profiles.orgs
		WHERE owner_user_id=$1::uuid
		  AND is_personal=true
		  AND deleted_at IS NULL
	`, userID).Scan(&orgID, &orgReserved); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrReservedAccountNotFound
		}
		return "", "", err
	}
	if !orgReserved {
		return "", "", ErrReservedAccountClaimed
	}

	phc, err := pwhash.HashArgon2id(newPassword)
	if err != nil {
		return "", "", err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO profiles.user_passwords (user_id, password_hash, hash_algo)
		VALUES ($1::uuid, $2, 'argon2id')
		ON CONFLICT (user_id)
		DO UPDATE SET password_hash=EXCLUDED.password_hash, hash_algo='argon2id', password_updated_at=now()
	`, userID, phc); err != nil {
		return "", "", err
	}

	if email != nil {
		trimmed := strings.TrimSpace(*email)
		if _, err := tx.Exec(ctx, `
			UPDATE profiles.users
			SET email=NULLIF(lower($2), ''),
				email_verified=false,
				updated_at=now()
			WHERE id=$1::uuid
		`, userID, trimmed); err != nil {
			return "", "", err
		}
	}
	if phone != nil {
		trimmed := strings.TrimSpace(*phone)
		if _, err := tx.Exec(ctx, `
			UPDATE profiles.users
			SET phone_number=NULLIF($2, ''),
				phone_verified=false,
				updated_at=now()
			WHERE id=$1::uuid
		`, userID, trimmed); err != nil {
			return "", "", err
		}
	}

	if err := s.setUserReservedTx(ctx, tx, userID, false); err != nil {
		return "", "", err
	}
	if err := s.setOrgReservedTx(ctx, tx, orgID, false); err != nil {
		return "", "", err
	}
	if err := s.setOrgNamespaceStateTx(ctx, tx, orgID, OwnerNamespaceStateRegistered); err != nil {
		return "", "", err
	}
	if err := s.deleteOwnerReservedNameTx(ctx, tx, slug); err != nil {
		return "", "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}
	return strings.TrimSpace(userID), strings.TrimSpace(orgID), nil
}
