package engine

import (
	"context"
	stdlog "log"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
)

// finalizeChangeEmail applies a verified email change to an existing user,
// moves its email factor to the new address, revokes every other session and
// tells the previous address.
func (s *Engine) finalizeChangeEmail(ctx context.Context, rec pendingChange, keepSessionID *string) (string, error) {
	u, err := s.getUserByID(ctx, rec.UserID)
	if err != nil || u == nil {
		return "", errOrUnauthorized(err)
	}

	// If the target already matches the current email, just mark it verified.
	if u.Email != nil && strings.EqualFold(*u.Email, rec.Target) {
		receipt, err := s.verifyContactProof(ctx, rec.UserID, rec.Version, passwordlessChannelEmail, rec.Target, keepSessionID)
		return receipt.ID, err
	}

	// Re-check uniqueness before committing (not reserved at request time).
	if existing, _ := s.getUserByEmail(ctx, rec.Target); existing != nil && existing.ID != rec.UserID {
		return "", iam.ErrEmailInUse
	}

	if err := s.applyContactChange(ctx, rec, passwordlessChannelEmail, keepSessionID, func(q *db.Queries) error {
		if err := mapUserUniqueViolation(q.UserApplyEmailChange(ctx, db.UserApplyEmailChangeParams{ID: rec.UserID, Email: rec.Target})); err != nil {
			return err
		}
		// The account asked for this change with MFA and just proved the new
		// mailbox, so its email factor moves there. Staff, system and import
		// changes never move it (P3, R3).
		return q.MFASetEmailFactorAddress(ctx, db.MFASetEmailFactorAddressParams{UserID: rec.UserID, Email: rec.Target})
	}); err != nil {
		return "", err
	}
	if u.Email != nil && s.email != nil {
		s.notifyContactChanged(rec.UserID, s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessageContactChanged, To: *u.Email, Username: deref(u.Username),
			Language: s.userLanguage(ctx, rec.UserID), ContactChange: &iam.ContactChange{Field: iam.ContactEmail, NewValue: rec.Target}}))
	}
	return rec.UserID, nil
}

// finalizeChangePhone is finalizeChangeEmail for the phone channel.
func (s *Engine) finalizeChangePhone(ctx context.Context, rec pendingChange, keepSessionID *string) (string, error) {
	u, err := s.getUserByID(ctx, rec.UserID)
	if err != nil || u == nil {
		return "", errOrUnauthorized(err)
	}

	if u.PhoneNumber != nil && strings.EqualFold(*u.PhoneNumber, rec.Target) {
		receipt, err := s.verifyContactProof(ctx, rec.UserID, rec.Version, passwordlessChannelSMS, rec.Target, keepSessionID)
		return receipt.ID, err
	}

	if existing, _ := s.getUserByPhone(ctx, rec.Target); existing != nil && existing.ID != rec.UserID {
		return "", iam.ErrPhoneInUse
	}

	if err := s.applyContactChange(ctx, rec, passwordlessChannelSMS, keepSessionID, func(q *db.Queries) error {
		return mapUserUniqueViolation(q.UserApplyPhoneChange(ctx, db.UserApplyPhoneChangeParams{ID: rec.UserID, PhoneNumber: &rec.Target}))
	}); err != nil {
		return "", err
	}
	if u.PhoneNumber != nil && s.sms != nil {
		s.notifyContactChanged(rec.UserID, s.sendSMS(ctx, iam.SMSMessage{Kind: iam.MessageContactChanged, To: *u.PhoneNumber,
			Language: s.userLanguage(ctx, rec.UserID), ContactChange: &iam.ContactChange{Field: iam.ContactPhone, NewValue: rec.Target}}))
	}
	return rec.UserID, nil
}

// applyContactChange commits a recovery-identifier change and the revocation of
// every other session in ONE transaction (as finishPasswordReset does, #199): a
// hijacked contact must never go live while the sessions that hijacked it survive.
// It is a proof like any other (ak#417): re-checked against the account's
// unproven addresses under the account lock (the version-bound record already
// dies with any contact change), and when it replaces the account's only
// unproven address it first retires the pre-proof credentials.
func (s *Engine) applyContactChange(ctx context.Context, rec pendingChange, channel string, keepSessionID *string, apply func(*db.Queries) error) error {
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.New(tx)
	locked, err := s.lockLoginAccount(ctx, q, rec.UserID, rec.Version)
	if err != nil {
		return err
	}
	if err := refuseProofBesideUnproven(locked, channel); err != nil {
		return err
	}
	userID := rec.UserID
	proven, err := s.retirePreProofCredentials(ctx, tx, userID, keepSessionID)
	if err != nil {
		return err
	}
	before, err := readAccountIdentity(ctx, tx, userID)
	if err != nil {
		return err
	}
	if err := apply(q); err != nil {
		return err
	}
	changes, err := identityChanges(ctx, tx, userID, before)
	if err != nil {
		return err
	}
	if err := s.emitEvents(ctx, tx, iam.UserActor(userID), changes...); err != nil {
		return err
	}
	revoked, err := revokeSessionsTx(ctx, q, userID, s.accountIssuers(), keepSessionID)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.logRevokedSessions(ctx, userID, proven, string(authflow.SessionRevokeReasonContactProven))
	s.logRevokedSessions(ctx, userID, revoked, string(authflow.SessionRevokeReasonContactChange))
	return nil
}

// notifyContactChanged tells the previous address it was replaced. Best-effort:
// the change is already committed, so a delivery failure is logged (without the
// address) rather than reported as a failed confirmation.
func (s *Engine) notifyContactChanged(userID string, err error) {
	if err != nil {
		stdlog.Printf("[authkit/security] contact-change notice to the previous address failed for user %s: %v", userID, err)
	}
}
