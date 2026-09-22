package embedded

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// Provider links: linking and unlinking external identity providers and
// writing provider usernames.

func (s *engine) SetProviderUsername(ctx context.Context, userID, provider, subject, username string) error {
	return s.setProviderUsername(ctx, userID, provider, subject, username)
}

// UserProfileLinks returns the user's linked provider slugs (non-null) and username
// aliases — the two extra lists GET /me needs beyond AdminGetUser. Keeps raw
// db.Queries out of the HTTP layer, which previously built its own db handle inline.
func (s *engine) UserProfileLinks(ctx context.Context, userID string) (providerSlugs []string, aliases []string, err error) {
	if s.pg == nil {
		return nil, nil, nil
	}
	providerSlugs, err = s.q.UserProviderSlugs(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	aliases, err = s.q.UserSlugAliases(ctx, db.UserSlugAliasesParams{UserID: userID, AtTime: s.namingNow()})
	if err != nil {
		return nil, nil, err
	}
	return providerSlugs, aliases, nil
}

// HasProviderLink reports whether userID holds a link to subject-issuer under
// providerSlug — the step-up gate's "is this the user's own provider" check.
func (s *engine) HasProviderLink(ctx context.Context, userID, issuer, providerSlug string) (bool, error) {
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
func (s *engine) ProviderSlugs(ctx context.Context, userID string) ([]string, error) {
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
func (s *engine) UnlinkProviderUnlessLast(ctx context.Context, userID, provider string) (bool, error) {
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
func (s *engine) GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error) {
	return s.getProviderLinkByIssuerInternal(ctx, issuer, subject)
}

// LinkProviderByIssuer is a trusted host/import operation. Browser flows use
// ExternalLoginInput.Link, whose initiating session is checked at commit.
func (s *engine) LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error {
	if s.pg == nil {
		return nil
	}
	verified, err := linkProviderByIssuer(ctx, s.q, userID, issuer, providerSlug, subject, email)
	if err != nil {
		return err
	}
	if providerSlug == SolanaProviderSlug && issuer == s.solanaIssuer() && verified {
		s.maybeResolveSolanaSNSAfterLink(ctx, userID, subject)
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
			return false, authkit.ErrProviderAlreadyLinked
		}
		if isUniqueViolation(err, "user_providers_user_id_issuer_key") {
			return false, authkit.ErrProviderChangeRequiresUnlink
		}
		return false, err
	}
	return linked.VerifiedAt != nil, nil
}

func (s *engine) getProviderLinkByIssuerInternal(ctx context.Context, issuer, subject string) (userID string, email *string, err error) {
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
func (s *engine) setProviderUsername(ctx context.Context, userID, issuer, subject, username string) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserProviderSetUsername(ctx, db.UserProviderSetUsernameParams{UserID: userID, Issuer: issuer, Subject: subject, Username: username})
}
