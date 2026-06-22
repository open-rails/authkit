package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

var (
	ErrReservedAccountNotFound = errors.New("reserved_account_not_found")
	ErrReservedAccountClaimed  = errors.New("reserved_account_claimed")
)

func normalizeReservedSlug(slug string) string {
	return strings.ToLower(strings.TrimSpace(slug))
}

func (s *Service) setUserReservedTx(ctx context.Context, tx pgx.Tx, userID string, reserved bool) error {
	if tx == nil {
		return fmt.Errorf("tx required")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	return s.qtx(tx).UserSetReserved(ctx, db.UserSetReservedParams{ID: userID, Reserved: reserved})
}

func (s *Service) setOrgReservedTx(ctx context.Context, tx pgx.Tx, orgID string, reserved bool) error {
	if tx == nil {
		return fmt.Errorf("tx required")
	}
	if strings.TrimSpace(orgID) == "" {
		return fmt.Errorf("invalid_org")
	}
	return s.qtx(tx).OrgSetReserved(ctx, db.OrgSetReservedParams{ID: orgID, Reserved: reserved})
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
	qtx := s.qtx(tx)
	if err := qtx.UserPasswordDelete(ctx, userID); err != nil {
		return err
	}
	if err := qtx.UserProvidersDeleteByUser(ctx, userID); err != nil {
		return err
	}
	return qtx.UserClearLoginIdentifiers(ctx, userID)
}

// Deprecated: use s.Users().GetUserMetadata.
func (s *Service) GetUserMetadata(ctx context.Context, userID string) (map[string]any, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	raw, err := s.q.UserMetadata(ctx, userID)
	if err != nil {
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

// Deprecated: use s.Users().PatchUserMetadata.
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
	n, err := s.q.UserMetadataPatch(ctx, db.UserMetadataPatchParams{ID: userID, Patch: raw})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// Deprecated: use s.Orgs().GetOrgMetadata.
func (s *Service) GetOrgMetadata(ctx context.Context, orgID string) (map[string]any, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(orgID) == "" {
		return nil, fmt.Errorf("invalid_org")
	}
	raw, err := s.q.OrgMetadata(ctx, orgID)
	if err != nil {
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

// Deprecated: use s.Orgs().PatchOrgMetadata.
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
	n, err := s.q.OrgMetadataPatch(ctx, db.OrgMetadataPatchParams{ID: orgID, Patch: raw})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrOrgNotFound
	}
	return nil
}

// Deprecated: use s.Orgs().IsOrgReserved.
func (s *Service) IsOrgReserved(ctx context.Context, orgID string) (bool, error) {
	state, err := s.GetOrgNamespaceState(ctx, orgID)
	if err != nil {
		return false, err
	}
	return state == OwnerNamespaceStateParkedOrg, nil
}

// ReserveAccount reserves a namespace slug without requiring a same-slug login user.
// For legacy placeholder rows, it still enforces non-loginable reserved invariants.
// Deprecated: use s.Orgs().ReserveAccount.
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

	qtx := s.qtx(tx)
	if row, err := qtx.OrgIDReservedBySlug(ctx, slug); err == nil {
		orgID = strings.TrimSpace(row.ID)
		if !row.Reserved {
			return "", "", false, ErrReservedAccountClaimed
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, err
	}

	switch row, err := qtx.UserIDReservedByUsername(ctx, &slug); {
	case err == nil:
		userID = strings.TrimSpace(row.ID)
		if !row.Reserved {
			return "", "", false, ErrReservedAccountClaimed
		}
	case errors.Is(err, pgx.ErrNoRows):
	default:
		return "", "", false, err
	}

	if strings.TrimSpace(userID) != "" && strings.TrimSpace(orgID) == "" {
		switch row, err := qtx.PersonalOrgIDSlugReservedByOwner(ctx, userID); {
		case err == nil:
			orgID = strings.TrimSpace(row.ID)
			if !row.Reserved {
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
