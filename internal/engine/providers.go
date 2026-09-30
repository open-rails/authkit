package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/provider"
)

// Provider links: linking and unlinking external identity providers and
// writing provider usernames.

// HasProviderLink reports whether userID holds a link to subject-issuer under
// providerSlug — the step-up gate's "is this the user's own provider" check.
func (s *Engine) HasProviderLink(ctx context.Context, userID, issuer, providerSlug string) (bool, error) {
	if s.pg == nil {
		return false, nil
	}
	slug := strings.TrimSpace(providerSlug)
	return s.q.UserProviderLinkExists(ctx, db.UserProviderLinkExistsParams{
		UserID:       strings.TrimSpace(userID),
		Issuer:       strings.TrimSpace(issuer),
		ProviderSlug: &slug,
	})
}

// ProviderSlugs returns the distinct provider slugs linked to userID.
func (s *Engine) ProviderSlugs(ctx context.Context, userID string) ([]string, error) {
	if s.pg == nil {
		return nil, nil
	}
	return s.q.UserProviderSlugsDistinct(ctx, strings.TrimSpace(userID))
}

// UnlinkProvider removes the account's link to provider unless it is the
// account's last way to sign in: provider_not_linked when nothing is linked
// under that name, cannot_unlink_last_login_method when no other sign-in
// method would remain. An imported claim not yet verified signs nobody in, so
// it always goes. The check and the delete hold the account lock every
// credential change takes, so two unlinks cannot each leave the other last.
func (s *Engine) UnlinkProvider(ctx context.Context, userID, provider string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.qtx(tx)
	account, err := q.UserCredentialVersionForUpdate(ctx, userID)
	if err != nil {
		return err
	}
	_, err = q.UserProviderUnverifiedForUpdate(ctx, db.UserProviderUnverifiedForUpdateParams{UserID: userID, ProviderSlug: &provider})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		slugs, err := q.UserProviderSlugsDistinct(ctx, userID)
		if err != nil {
			return err
		}
		if !slices.Contains(slugs, provider) {
			return errmodel.ErrProviderNotLinked
		}
		others := slices.DeleteFunc(slugs, func(slug string) bool { return slug == provider || !s.signsInWith(slug) })
		if len(others) == 0 {
			ok, err := s.hasSignInBesidesProviders(ctx, tx, userID, account)
			if err != nil {
				return err
			}
			if !ok {
				return errmodel.ErrCannotUnlinkLastLoginMethod
			}
		}
	case err != nil:
		return err
	}
	if err := q.UserProviderDeleteBySlug(ctx, db.UserProviderDeleteBySlugParams{UserID: userID, ProviderSlug: &provider}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// signsInWith reports whether a provider link under slug is a way to sign in
// here: a configured provider, or a wallet while Solana is on.
func (s *Engine) signsInWith(slug string) bool {
	if slug == solanaProviderSlug {
		return s.cfg.SolanaNetwork != ""
	}
	return slices.ContainsFunc(s.providers, func(p provider.Provider) bool { return p != nil && strings.EqualFold(p.Name(), slug) })
}

// hasSignInBesidesProviders reports whether the account signs in some way
// other than a provider: a password, a passkey, a device key, or a
// passwordless code to its email or phone.
func (s *Engine) hasSignInBesidesProviders(ctx context.Context, tx pgx.Tx, userID string, account db.UserCredentialVersionForUpdateRow) (bool, error) {
	q := s.qtx(tx)
	if s.cfg.Registration.PasswordlessLogin && (account.Email != nil && s.email != nil || account.PhoneNumber != nil && s.sms != nil) {
		return true, nil
	}
	if ok, err := q.UserHasPassword(ctx, userID); ok || err != nil {
		return ok, err
	}
	if ok, err := s.holdsPasskey(ctx, tx, userID); ok || err != nil {
		return ok, err
	}
	if !s.cfg.DeviceKeys.Enabled {
		return false, nil
	}
	keys, err := q.DeviceKeysByUser(ctx, userID)
	return slices.ContainsFunc(keys, func(k db.UserDeviceKey) bool { return k.RevokedAt == nil }), err
}

// Issuer-based provider link helpers (preferred)
func (s *Engine) GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error) {
	return s.getProviderLinkByIssuerInternal(ctx, issuer, subject)
}

// LinkProvider links an external identity to a live account as a login
// method, as a host operation. Browser flows use ExternalLoginInput.Link, whose
// initiating session is checked at commit.
func (s *Engine) LinkProvider(ctx context.Context, userID string, l iam.ProviderLink, opts ...ops.Option) error {
	if err := noOptions("LinkProvider", opts); err != nil {
		return err
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	userID = strings.TrimSpace(userID)
	l.Issuer, l.Subject, l.Provider = strings.TrimSpace(l.Issuer), strings.TrimSpace(l.Subject), strings.TrimSpace(l.Provider)
	if l.Issuer == "" || l.Subject == "" {
		return fmt.Errorf("authkit: a provider link needs an issuer and a subject")
	}
	var live bool
	if isUUID(userID) {
		var err error
		if live, err = s.q.UserNotDeleted(ctx, userID); err != nil {
			return err
		}
	}
	if !live {
		return iam.ErrUserNotFound
	}
	return s.linkProvider(ctx, userID, l)
}

// linkProvider links l to userID, for a caller that proved it.
func (s *Engine) linkProvider(ctx context.Context, userID string, l iam.ProviderLink) error {
	verified, err := linkProviderByIssuer(ctx, s.q, userID, l.Issuer, l.Provider, l.Subject, nullable(strings.TrimSpace(l.Email)))
	if err != nil {
		return err
	}
	if l.Provider == solanaProviderSlug && l.Issuer == s.solanaIssuer() && verified {
		s.maybeResolveSolanaSNSAfterLink(ctx, userID, l.Subject)
	}
	return nil
}

func linkProviderByIssuer(ctx context.Context, q *db.Queries, userID, issuer, providerSlug, subject string, email *string) (bool, error) {
	providerID, err := newUUIDV7String()
	if err != nil {
		return false, err
	}
	var slug *string
	if providerSlug != "" {
		slug = &providerSlug
	}
	linked, err := q.UserProviderUpsertByIssuer(ctx, db.UserProviderUpsertByIssuerParams{
		ID:              providerID,
		UserID:          userID,
		Issuer:          issuer,
		ProviderSlug:    slug,
		Subject:         subject,
		EmailAtProvider: email,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, errmodel.ErrProviderAlreadyLinked
		}
		if isUniqueViolation(err, "user_providers_user_id_issuer_key") {
			return false, errmodel.ErrProviderChangeRequiresUnlink
		}
		return false, err
	}
	return linked.VerifiedAt != nil, nil
}

func (s *Engine) getProviderLinkByIssuerInternal(ctx context.Context, issuer, subject string) (userID string, email *string, err error) {
	if s.pg == nil {
		return "", nil, nil
	}
	row, err := s.q.ProviderLinkByIssuer(ctx, db.ProviderLinkByIssuerParams{Issuer: issuer, Subject: subject})
	if err != nil {
		return "", nil, err
	}
	return row.UserID, row.EmailAtProvider, nil
}

// setProviderUsername stores a provider-specific username into profile jsonb as {"username": <value>}.
func (s *Engine) setProviderUsername(ctx context.Context, userID, issuer, subject, username string) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserProviderSetUsername(ctx, db.UserProviderSetUsernameParams{UserID: userID, Issuer: issuer, Subject: subject, Username: username})
}
