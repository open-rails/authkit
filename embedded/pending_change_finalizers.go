package embedded

import (
	"context"
	stdlog "log"
	"strings"

	"github.com/open-rails/authkit/internal/db"
)

// finalizeChangeEmail applies a verified email change to an existing user,
// revokes every other session and tells the previous address.
func (s *Client) finalizeChangeEmail(ctx context.Context, rec pendingChange, keepSessionID *string) (string, error) {
	u, err := s.getUserByID(ctx, rec.UserID)
	if err != nil || u == nil {
		return "", errOrUnauthorized(err)
	}

	// If the target already matches the current email, just mark it verified.
	if u.Email != nil && strings.EqualFold(*u.Email, rec.Target) {
		receipt, err := s.verifyContactProof(ctx, rec.UserID, rec.Version, PasswordlessChannelEmail, rec.Target)
		return receipt.ID, err
	}

	// Re-check uniqueness before committing (not reserved at request time).
	if existing, _ := s.getUserByEmail(ctx, rec.Target); existing != nil && existing.ID != rec.UserID {
		return "", ErrEmailInUse
	}

	if err := s.applyContactChange(ctx, rec, keepSessionID, func(q *db.Queries) error {
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
		receipt, err := s.verifyContactProof(ctx, rec.UserID, rec.Version, PasswordlessChannelSMS, rec.Target)
		return receipt.ID, err
	}

	if existing, _ := s.getUserByPhone(ctx, rec.Target); existing != nil && existing.ID != rec.UserID {
		return "", ErrPhoneInUse
	}

	if err := s.applyContactChange(ctx, rec, keepSessionID, func(q *db.Queries) error {
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
func (s *Client) applyContactChange(ctx context.Context, rec pendingChange, keepSessionID *string, apply func(*db.Queries) error) error {
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.New(db.ForSchema(tx, s.dbSchema()))
	if _, err := s.lockLoginAccount(ctx, q, rec.UserID, rec.Version); err != nil {
		return err
	}
	userID := rec.UserID
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
