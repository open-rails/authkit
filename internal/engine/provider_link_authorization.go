package engine

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
)

// The account lock serializes credential/liveness changes; the session lock
// serializes every revocation path. Linking never mints a replacement session.
func (s *Engine) completeProviderLink(ctx context.Context, link authflow.ExternalLinkAuthorization, id authflow.ExternalIdentity, email *string) error {
	if s.pg == nil || link.UserID == "" || link.SessionID == "" || link.AuthenticatedAt.IsZero() {
		return errmodel.E(errmodel.CodeAuthRequiredForLink)
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	account, err := q.UserCredentialVersionForUpdate(ctx, link.UserID)
	if err != nil {
		return err
	}
	if account.DeletedAt != nil || account.BannedAt != nil && (account.BannedUntil == nil || account.BannedUntil.After(time.Now())) {
		return errmodel.ErrUserBanned
	}
	if err := requireProvenContactOn(ctx, tx, link.UserID); err != nil {
		return err
	}
	reserved, err := q.UserIsReserved(ctx, link.UserID)
	if err != nil {
		return err
	}
	if reserved {
		return errmodel.ErrUserBanned
	}
	session, err := q.SessionFreshSinceForUpdate(ctx, db.SessionFreshSinceForUpdateParams{UserID: link.UserID, SessionID: link.SessionID, Issuer: s.cfg.Token.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		return errmodel.E(errmodel.CodeAuthRequiredForLink)
	}
	if err != nil {
		return err
	}
	now := time.Now()
	if link.AuthenticatedAt.After(now) || now.Sub(link.AuthenticatedAt) >= authflow.SensitiveActionFreshAuthWindow || session.FreshSince.Before(link.AuthenticatedAt) {
		return errmodel.ErrStepUpRequired
	}
	// MFA mutations take the same account lock, so a factor newly enabled while
	// the browser was at its provider cannot be skipped at completion.
	settings, err := q.MFASettingsByUser(ctx, link.UserID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if s.TwoFactorEnabled() && settings.Enabled && !hasAuthMethod(session.AuthMethods, "mfa") && !hasAuthMethod(session.AuthMethods, "otp") {
		return errmodel.ErrStepUpRequired
	}
	if _, err := linkProviderByIssuer(ctx, q, link.UserID, id.Issuer, id.Provider, id.Subject, email); err != nil {
		return err
	}
	if id.PreferredUsername != "" {
		if err := q.UserProviderSetUsername(ctx, db.UserProviderSetUsernameParams{UserID: link.UserID, Issuer: id.Issuer, Subject: id.Subject, Username: id.PreferredUsername}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
