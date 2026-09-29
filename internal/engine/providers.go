package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
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

// UnlinkProviderUnlessLast atomically removes the provider link only if the user
// retains a login method afterward (a password, or another provider). Returns
// (false, nil) when removal would strip the last login method. The check and the
// delete run in one transaction, and UserProviderCountForUpdate locks the user's
// provider rows so two concurrent unlinks of different providers cannot both pass
// the "not last" check and leave the user with zero login methods.
func (s *Engine) UnlinkProviderUnlessLast(ctx context.Context, userID, provider string) (bool, error) {
	if s.pg == nil {
		return false, nil
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.qtx(tx)
	_, unverifiedErr := q.UserProviderUnverifiedForUpdate(ctx, db.UserProviderUnverifiedForUpdateParams{
		UserID:       userID,
		ProviderSlug: &provider,
	})
	if unverifiedErr != nil && !errors.Is(unverifiedErr, pgx.ErrNoRows) {
		return false, unverifiedErr
	}
	// An imported provider claim is visible so the user can verify or remove it,
	// but it is not a login method. Removing it therefore cannot strip the last
	// credential and must not be rejected by the credential-count guard below.
	// Lock only unverified rows here so verified-provider unlinks retain the
	// established all-provider lock order below.
	if unverifiedErr == nil {
		if err := q.UserProviderDeleteBySlug(ctx, db.UserProviderDeleteBySlugParams{UserID: userID, ProviderSlug: &provider}); err != nil {
			return false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return false, err
		}
		return true, nil
	}
	links, err := q.UserProviderCountForUpdate(ctx, userID)
	if err != nil {
		return false, err
	}
	hasPwd, err := q.UserHasPassword(ctx, userID)
	if err != nil {
		return false, err
	}
	// Mirror the prior guard semantics (no password AND ≤1 provider ⇒ this is the
	// last login method), now evaluated under the row lock.
	if !hasPwd && links <= 1 {
		return false, nil
	}
	if err := q.UserProviderDeleteBySlug(ctx, db.UserProviderDeleteBySlugParams{UserID: userID, ProviderSlug: &provider}); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// Issuer-based provider link helpers (preferred)
func (s *Engine) GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error) {
	return s.getProviderLinkByIssuerInternal(ctx, issuer, subject)
}

// LinkProvider links an external identity to a live account as a login
// method, under the operator. Browser flows use ExternalLoginInput.Link, whose
// initiating session is checked at commit.
func (s *Engine) LinkProvider(ctx context.Context, a iam.Actor, userID string, l iam.ProviderLink) error {
	if err := requireOperator(a); err != nil {
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
		if err := s.pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid AND deleted_at IS NULL)`, userID).Scan(&live); err != nil {
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
