package core

import (
	"context"
	"fmt"
	"strings"
)

// finalizeRegisterEmail completes an email+password signup: it enforces
// "first to verify wins" (email/username may have been taken since the pending
// record was created), creates the verified user, applies the preferred locale,
// and provisions a personal tenant when the host opts in. Mirrors the historical
// ConfirmPendingRegistration body.
func (s *Service) finalizeRegisterEmail(ctx context.Context, rec pendingChange) (string, error) {
	email := rec.Target
	username := rec.Username

	var exists bool
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM profiles.users
			WHERE email = lower($1) OR username = $2
		)
	`, email, username).Scan(&exists); err != nil {
		return "", err
	}
	if exists {
		// Someone else got there first — drop this pending registration.
		s.deletePendingChangeByTarget(ctx, KindRegisterEmail, email)
		return "", fmt.Errorf("email or username already taken")
	}

	uid, err := s.createVerifiedRegistrationUser(ctx, email, username, rec.PasswordHash)
	if err != nil {
		return "", err
	}
	if rec.PreferredLocale != "" {
		if err := s.SetPreferredLocale(ctx, uid, rec.PreferredLocale, "registration"); err != nil {
			return "", err
		}
	}
	if s.opts.AutoCreatePersonalTenantsEnabled() {
		if err := s.ensurePersonalOrgForUser(ctx, uid, username); err != nil {
			return "", err
		}
	}
	return uid, nil
}

// finalizeRegisterPhone completes a phone+password signup. Mirrors the historical
// ConfirmPendingPhoneRegistration body (no personal-tenant provisioning, matching
// prior behavior).
func (s *Service) finalizeRegisterPhone(ctx context.Context, rec pendingChange) (string, error) {
	phone := rec.Target
	username := rec.Username

	var exists bool
	if err := s.pg.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM profiles.users
			WHERE phone_number = $1 OR username = $2
		)
	`, phone, username).Scan(&exists); err != nil {
		return "", err
	}
	if exists {
		s.deletePendingChangeByTarget(ctx, KindRegisterPhone, phone)
		return "", fmt.Errorf("phone or username already taken")
	}

	uid, err := s.createPhoneRegistrationUser(ctx, phone, username, rec.PasswordHash, true)
	if err != nil {
		return "", err
	}
	if rec.PreferredLocale != "" {
		if err := s.SetPreferredLocale(ctx, uid, rec.PreferredLocale, "registration"); err != nil {
			return "", err
		}
	}
	return uid, nil
}

// finalizeChangeEmail applies a verified email change to an existing user.
// Mirrors the historical ConfirmEmailChange body (post token-consume).
func (s *Service) finalizeChangeEmail(ctx context.Context, rec pendingChange) (string, error) {
	u, err := s.getUserByID(ctx, rec.UserID)
	if err != nil || u == nil {
		return "", errOrUnauthorized(err)
	}

	// If the target already matches the current email, just mark it verified.
	if u.Email != nil && strings.EqualFold(*u.Email, rec.Target) {
		return rec.UserID, s.setEmailVerified(ctx, rec.UserID, true)
	}

	// Re-check uniqueness before committing (not reserved at request time).
	if existing, _ := s.getUserByEmail(ctx, rec.Target); existing != nil && existing.ID != rec.UserID {
		return "", fmt.Errorf("email already in use")
	}

	if _, err := s.pg.Exec(ctx, `UPDATE profiles.users SET email=lower($2), email_verified=true, updated_at=NOW() WHERE id=$1`, rec.UserID, rec.Target); err != nil {
		return "", err
	}
	return rec.UserID, nil
}

// finalizeChangePhone applies a verified phone change to an existing user.
// Mirrors the historical ConfirmPhoneChange body (post token-consume), including
// the uniqueness re-check added when phone-change optimistic pre-apply was removed.
func (s *Service) finalizeChangePhone(ctx context.Context, rec pendingChange) (string, error) {
	u, err := s.getUserByID(ctx, rec.UserID)
	if err != nil || u == nil {
		return "", errOrUnauthorized(err)
	}

	if u.PhoneNumber != nil && strings.EqualFold(*u.PhoneNumber, rec.Target) {
		return rec.UserID, s.setPhoneVerified(ctx, rec.UserID, true)
	}

	if existing, _ := s.getUserByPhone(ctx, rec.Target); existing != nil && existing.ID != rec.UserID {
		return "", fmt.Errorf("phone already in use")
	}

	if _, err := s.pg.Exec(ctx, `UPDATE profiles.users SET phone_number=$2, phone_verified=true, updated_at=NOW() WHERE id=$1`, rec.UserID, rec.Target); err != nil {
		return "", err
	}
	return rec.UserID, nil
}
