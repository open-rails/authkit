package embedded

import (
	"context"
	"errors"
	stdlog "log"
	"strings"

	"github.com/open-rails/authkit/internal/db"
)

// finalizeRegisterEmail completes an email+password signup: it enforces
// "first to verify wins" (email/username may have been taken since the pending
// record was created), creates the verified user, and applies the preferred
// language. Mirrors the historical ConfirmPendingRegistration body.
func (s *Client) finalizeRegisterEmail(ctx context.Context, rec pendingChange) (string, error) {
	email := rec.Target
	username := rec.Username

	// The insert is the availability check (#326): a race loser gets the typed
	// conflict and its pending registration is dropped.
	uid, err := s.createVerifiedRegistrationUser(ctx, email, username, rec.PasswordHash)
	if err != nil {
		if errors.Is(err, ErrEmailInUse) || errors.Is(err, ErrUsernameInUse) {
			s.deletePendingChangeByTarget(ctx, KindRegisterEmail, email)
		}
		return "", err
	}
	if err := s.consumeAccountRegistrationInvite(ctx, email, uid); err != nil {
		return "", err
	}
	if rec.PreferredLanguage != "" {
		if err := s.SetPreferredLanguage(ctx, uid, rec.PreferredLanguage); err != nil {
			return "", err
		}
	}
	return uid, nil
}

// finalizeRegisterPhone completes a phone+password signup. Mirrors the historical
// ConfirmPendingPhoneRegistration body (no permission-group provisioning, matching
// prior behavior).
func (s *Client) finalizeRegisterPhone(ctx context.Context, rec pendingChange) (string, error) {
	phone := rec.Target
	username := rec.Username

	uid, err := s.createPhoneRegistrationUser(ctx, phone, username, rec.PasswordHash, true)
	if err != nil {
		return "", err
	}
	if rec.PreferredLanguage != "" {
		if err := s.SetPreferredLanguage(ctx, uid, rec.PreferredLanguage); err != nil {
			return "", err
		}
	}
	return uid, nil
}

// finalizeChangeEmail applies a verified email change to an existing user,
// revokes every other session and tells the previous address.
func (s *Client) finalizeChangeEmail(ctx context.Context, rec pendingChange, keepSessionID *string) (string, error) {
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
		return "", ErrEmailInUse
	}

	if err := s.applyContactChange(ctx, rec.UserID, keepSessionID, func(q *db.Queries) error {
		return mapUserUniqueViolation(q.UserApplyEmailChange(ctx, db.UserApplyEmailChangeParams{ID: rec.UserID, Email: rec.Target}))
	}); err != nil {
		return "", err
	}
	if u.Email != nil && s.email != nil {
		old, username := *u.Email, ""
		if u.Username != nil {
			username = *u.Username
		}
		s.notifyContactChanged(ctx, rec.UserID, func(c context.Context) error {
			return s.email.SendContactChanged(c, old, username, ContactChange{Field: "email", NewValue: rec.Target})
		})
	}
	return rec.UserID, nil
}

// finalizeChangePhone is finalizeChangeEmail for the phone channel.
func (s *Client) finalizeChangePhone(ctx context.Context, rec pendingChange, keepSessionID *string) (string, error) {
	u, err := s.getUserByID(ctx, rec.UserID)
	if err != nil || u == nil {
		return "", errOrUnauthorized(err)
	}

	if u.PhoneNumber != nil && strings.EqualFold(*u.PhoneNumber, rec.Target) {
		return rec.UserID, s.setPhoneVerified(ctx, rec.UserID, true)
	}

	if existing, _ := s.getUserByPhone(ctx, rec.Target); existing != nil && existing.ID != rec.UserID {
		return "", ErrPhoneInUse
	}

	if err := s.applyContactChange(ctx, rec.UserID, keepSessionID, func(q *db.Queries) error {
		return mapUserUniqueViolation(q.UserApplyPhoneChange(ctx, db.UserApplyPhoneChangeParams{ID: rec.UserID, PhoneNumber: &rec.Target}))
	}); err != nil {
		return "", err
	}
	if u.PhoneNumber != nil && s.sms != nil {
		old := *u.PhoneNumber
		s.notifyContactChanged(ctx, rec.UserID, func(c context.Context) error {
			return s.sms.SendContactChanged(c, old, ContactChange{Field: "phone", NewValue: rec.Target})
		})
	}
	return rec.UserID, nil
}

// applyContactChange commits a recovery-identifier change and the revocation of
// every other session in ONE transaction (as finishPasswordReset does, #199): a
// hijacked contact must never go live while the sessions that hijacked it survive.
func (s *Client) applyContactChange(ctx context.Context, userID string, keepSessionID *string, apply func(*db.Queries) error) error {
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.New(db.ForSchema(tx, s.dbSchema()))
	if err := apply(q); err != nil {
		return err
	}
	var revoked []string
	if keepSessionID != nil && *keepSessionID != "" {
		revoked, err = q.SessionsRevokeAllExcept(ctx, db.SessionsRevokeAllExceptParams{UserID: userID, Issuer: s.cfg.Token.Issuer, ID: *keepSessionID})
	} else {
		revoked, err = q.SessionsRevokeAll(ctx, db.SessionsRevokeAllParams{UserID: userID, Issuer: s.cfg.Token.Issuer})
	}
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	reason := string(SessionRevokeReasonContactChange)
	for _, sid := range revoked {
		s.logSessionRevoked(ctx, userID, sid, &reason)
	}
	return nil
}

// notifyContactChanged tells the previous address it was replaced. Best-effort:
// the change is already committed, so a delivery failure is logged (without the
// address) rather than reported as a failed confirmation.
func (s *Client) notifyContactChanged(ctx context.Context, userID string, send func(context.Context) error) {
	sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
	if err := s.withSendTimeout(sendCtx, send); err != nil {
		stdlog.Printf("[authkit/security] contact-change notice to the previous address failed for user %s: %v", userID, err)
	}
}
