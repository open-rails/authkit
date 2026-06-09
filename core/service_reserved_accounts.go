package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

var (
	ErrReservedAccountNotFound = errors.New("reserved_account_not_found")
	ErrReservedAccountClaimed  = errors.New("reserved_account_claimed")
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

func (s *Service) setTenantReservedTx(ctx context.Context, tx pgx.Tx, tenantID string, reserved bool) error {
	if tx == nil {
		return fmt.Errorf("tx required")
	}
	if strings.TrimSpace(tenantID) == "" {
		return fmt.Errorf("invalid_org")
	}
	_, err := tx.Exec(ctx, `
		UPDATE profiles.tenants
		SET metadata=jsonb_set(COALESCE(metadata, '{}'::jsonb), '{reserved}', to_jsonb($2::boolean), true),
			updated_at=now()
		WHERE id=$1::uuid
	`, tenantID, reserved)
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

func (s *Service) GetTenantMetadata(ctx context.Context, tenantID string) (map[string]any, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(tenantID) == "" {
		return nil, fmt.Errorf("invalid_org")
	}
	var raw []byte
	if err := s.pg.QueryRow(ctx, `SELECT COALESCE(metadata, '{}'::jsonb) FROM profiles.tenants WHERE id=$1::uuid AND deleted_at IS NULL`, tenantID).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTenantNotFound
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

func (s *Service) PatchTenantMetadata(ctx context.Context, tenantID string, patch map[string]any) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if strings.TrimSpace(tenantID) == "" {
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
		UPDATE profiles.tenants
		SET metadata=COALESCE(metadata, '{}'::jsonb) || $2::jsonb,
			updated_at=now()
		WHERE id=$1::uuid AND deleted_at IS NULL
	`, tenantID, raw)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTenantNotFound
	}
	return nil
}

func (s *Service) IsTenantReserved(ctx context.Context, tenantID string) (bool, error) {
	state, err := s.GetTenantNamespaceState(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return state == OwnerNamespaceStateParkedTenant, nil
}

// ReserveAccount reserves a namespace slug without requiring a same-slug login user.
// For legacy placeholder rows, it still enforces non-loginable reserved invariants.
func (s *Service) ReserveAccount(ctx context.Context, slug string) (userID, tenantID string, reserved bool, err error) {
	if err := s.requirePG(); err != nil {
		return "", "", false, err
	}
	slug = normalizeReservedSlug(slug)
	if err := validateTenantSlug(slug); err != nil {
		return "", "", false, err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", "", false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		existingTenantID       string
		existingTenantReserved bool
	)
	if err := tx.QueryRow(ctx, `
		SELECT id::text,
		       CASE
		         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
		         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
		         ELSE false
		       END
		FROM profiles.tenants
		WHERE slug=$1
		  AND deleted_at IS NULL
	`, slug).Scan(&existingTenantID, &existingTenantReserved); err == nil {
		tenantID = strings.TrimSpace(existingTenantID)
		if !existingTenantReserved {
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
		WHERE username=$1
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

	if strings.TrimSpace(userID) != "" && strings.TrimSpace(tenantID) == "" {
		var existingTenantSlug string
		switch err := tx.QueryRow(ctx, `
			SELECT id::text,
			       slug,
			       CASE
			         WHEN jsonb_typeof(COALESCE(metadata, '{}'::jsonb)->'reserved')='boolean'
			         THEN (COALESCE(metadata, '{}'::jsonb)->>'reserved')::boolean
			         ELSE false
			       END
			FROM profiles.tenants
			WHERE owner_user_id=$1::uuid
			  AND is_personal=true
			  AND deleted_at IS NULL
		`, userID).Scan(&existingTenantID, &existingTenantSlug, &existingTenantReserved); {
		case err == nil:
			tenantID = strings.TrimSpace(existingTenantID)
			if !existingTenantReserved {
				return "", "", false, ErrReservedAccountClaimed
			}
		case errors.Is(err, pgx.ErrNoRows):
		default:
			return "", "", false, err
		}
	}

	if strings.TrimSpace(userID) == "" && strings.TrimSpace(tenantID) == "" {
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

	if strings.TrimSpace(tenantID) != "" {
		if err := s.setTenantReservedTx(ctx, tx, tenantID, true); err != nil {
			return "", "", false, err
		}
		if err := s.setTenantNamespaceStateTx(ctx, tx, tenantID, OwnerNamespaceStateParkedTenant); err != nil {
			return "", "", false, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", "", false, err
	}
	return strings.TrimSpace(userID), strings.TrimSpace(tenantID), true, nil
}
