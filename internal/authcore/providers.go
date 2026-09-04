package authcore

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
)

// This file holds the provider-link cluster extracted from service.go
// (Stage 13 of agents/audit/02-service-split.md): linking and unlinking
// external identity providers and reading/writing provider usernames.

// Additional public helpers used by OIDC flow
func (s *Service) LinkProvider(ctx context.Context, userID, provider, subject string, email *string) error {
	return s.linkProvider(ctx, userID, provider, subject, email)
}

func (s *Service) SetProviderUsername(ctx context.Context, userID, provider, subject, username string) error {
	return s.setProviderUsername(ctx, userID, provider, subject, username)
}

// ProviderUsernames returns each user's stored username for the given provider
// in ONE call (#220 — replaces the single GetProviderUsername). Map keyed by
// user id; users without a stored username are absent.
func (s *Service) ProviderUsernames(ctx context.Context, userIDs []string, provider string) (map[string]string, error) {
	out := map[string]string{}
	if s.pg == nil || len(userIDs) == 0 {
		return out, nil
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	// Batch form of the sqlc UserProviderUsername query: one row per user (their
	// most recent link for the provider). Raw SQL by the invite-links precedent.
	rows, err := q.Query(ctx,
		`SELECT DISTINCT ON (user_id) user_id::text, profile->>'username' AS username
		   FROM profiles.user_providers
		  WHERE user_id = ANY($1::uuid[]) AND provider_slug = $2
		    AND verified_at IS NOT NULL
		  ORDER BY user_id, created_at DESC`,
		userIDs, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var username *string
		if err := rows.Scan(&id, &username); err != nil {
			return nil, err
		}
		if username != nil && *username != "" {
			out[id] = *username
		}
	}
	return out, rows.Err()
}

// Provider link management
func (s *Service) countProviderLinks(ctx context.Context, userID string) int {
	if s.pg == nil {
		return 0
	}
	n, _ := s.q.UserProvidersCount(ctx, userID)
	return int(n)
}

func (s *Service) unlinkProvider(ctx context.Context, userID, provider string) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserProviderDeleteBySlug(ctx, db.UserProviderDeleteBySlugParams{UserID: userID, ProviderSlug: &provider})
}

// Public wrappers
func (s *Service) CountProviderLinks(ctx context.Context, userID string) int {
	return s.countProviderLinks(ctx, userID)
}

func (s *Service) UnlinkProvider(ctx context.Context, userID, provider string) error {
	return s.unlinkProvider(ctx, userID, provider)
}

// UserProfileLinks returns the user's linked provider slugs (non-null) and username
// aliases — the two extra lists GET /me needs beyond AdminGetUser. Keeps raw
// db.Queries out of the HTTP layer, which previously built its own db handle inline.
func (s *Service) UserProfileLinks(ctx context.Context, userID string) (providerSlugs []string, aliases []string, err error) {
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

// UnlinkProviderUnlessLast atomically removes the provider link only if the user
// retains a login method afterward (a password, or another provider). Returns
// (false, nil) when removal would strip the last login method. The check and the
// delete run in one transaction, and UserProviderCountForUpdate locks the user's
// provider rows so two concurrent unlinks of different providers cannot both pass
// the "not last" check and leave the user with zero login methods.
func (s *Service) UnlinkProviderUnlessLast(ctx context.Context, userID, provider string) (bool, error) {
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
func (s *Service) GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error) {
	return s.getProviderLinkByIssuerInternal(ctx, issuer, subject)
}

func (s *Service) LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error {
	// Both unique constraints arbitrate ownership atomically. A new subject
	// cannot replace the user's existing identity for this issuer.
	if s.pg == nil {
		return nil
	}
	providerID, err := newUUIDV7String()
	if err != nil {
		return err
	}
	var slug *string
	if providerSlug != "" {
		slug = &providerSlug
	}
	linked, err := s.q.UserProviderUpsertByIssuer(ctx, db.UserProviderUpsertByIssuerParams{
		ID:              providerID,
		UserID:          userID,
		Issuer:          issuer,
		ProviderSlug:    slug,
		Subject:         subject,
		EmailAtProvider: email,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authkit.ErrProviderAlreadyLinked
		}
		if isUniqueViolation(err, "user_providers_user_id_issuer_key") {
			return authkit.ErrProviderChangeRequiresUnlink
		}
		return err
	}
	if providerSlug == SolanaProviderSlug && issuer == s.solanaIssuer() && linked.VerifiedAt != nil {
		s.maybeResolveSolanaSNSAfterLink(ctx, userID, subject)
	}
	return nil
}

func (s *Service) getProviderLinkByIssuerInternal(ctx context.Context, issuer, subject string) (userID string, email *string, err error) {
	if s.pg == nil {
		return "", nil, nil
	}
	row, err := s.q.ProviderLinkByIssuer(ctx, db.ProviderLinkByIssuerParams{Issuer: issuer, Subject: subject})
	if err != nil {
		return "", nil, err
	}
	return row.UserID, row.EmailAtProvider, nil
}

func (s *Service) linkProvider(ctx context.Context, userID, issuer, subject string, email *string) error {
	return s.LinkProviderByIssuer(ctx, userID, issuer, "", subject, email)
}

// setProviderUsername stores a provider-specific username into profile jsonb as {"username": <value>}.
func (s *Service) setProviderUsername(ctx context.Context, userID, issuer, subject, username string) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserProviderSetUsername(ctx, db.UserProviderSetUsernameParams{UserID: userID, Issuer: issuer, Subject: subject, Username: username})
}
