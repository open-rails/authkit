package embedded

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// The account lock serializes credential/liveness changes; the session lock
// serializes every revocation path. Linking never mints a replacement session.
func (s *Runtime) completeProviderLink(ctx context.Context, link ExternalLinkAuthorization, id ExternalIdentity, email *string) error {
	if s.pg == nil || link.UserID == "" || link.SessionID == "" || link.AuthenticatedAt.IsZero() {
		return authkit.E(authkit.CodeAuthRequiredForLink)
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
		return ErrUserBanned
	}
	reserved, err := q.UserIsReserved(ctx, link.UserID)
	if err != nil {
		return err
	}
	if reserved {
		return ErrUserBanned
	}
	session, err := q.SessionFreshSinceForUpdate(ctx, db.SessionFreshSinceForUpdateParams{UserID: link.UserID, SessionID: link.SessionID, Issuer: s.cfg.Token.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		return authkit.E(authkit.CodeAuthRequiredForLink)
	}
	if err != nil {
		return err
	}
	now := time.Now()
	if link.AuthenticatedAt.After(now) || now.Sub(link.AuthenticatedAt) >= SensitiveActionFreshAuthWindow || session.FreshSince.Before(link.AuthenticatedAt) {
		return ErrStepUpRequired
	}
	// MFA mutations take the same account lock, so a factor newly enabled while
	// the browser was at its provider cannot be skipped at completion.
	settings, err := q.MFASettingsByUser(ctx, link.UserID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if s.TwoFactorEnabled() && settings.Enabled && !hasAuthMethod(session.AuthMethods, "mfa") && !hasAuthMethod(session.AuthMethods, "otp") {
		return ErrStepUpRequired
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
