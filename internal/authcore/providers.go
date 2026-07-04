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
	aliases, err = s.q.UserSlugAliases(ctx, userID)
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
	// Store provider slug for UI, enforce uniqueness on (issuer, subject) and (user_id, issuer).
	// The delete-other-subjects (allows switching e.g. Discord accounts) and the upsert run in
	// ONE transaction: a failure can't leave the user's old link deleted and the new one missing.
	if s.pg == nil {
		return nil
	}
	providerID, err := newUUIDV7String()
	if err != nil {
		return err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)

	// First delete any old link for this user+issuer with a different subject.
	if err := qtx.UserProviderDeleteOtherSubjects(ctx, db.UserProviderDeleteOtherSubjectsParams{UserID: userID, Issuer: issuer, Subject: subject}); err != nil {
		return err
	}
	// The upsert's ON CONFLICT (issuer, subject) DO UPDATE is constrained to the same user_id,
	// so a subject already owned by a DIFFERENT user yields zero affected rows (no cross-user
	// write) and RETURNING produces pgx.ErrNoRows — surfaced as a 409-class conflict.
	if _, err := qtx.UserProviderUpsertByIssuer(ctx, db.UserProviderUpsertByIssuerParams{
		ID:              providerID,
		UserID:          userID,
		Issuer:          issuer,
		ProviderSlug:    &providerSlug,
		Subject:         subject,
		EmailAtProvider: email,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authkit.ErrProviderAlreadyLinked
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	if providerSlug == SolanaProviderSlug && issuer == s.solanaIssuer() {
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
	if s.pg == nil {
		return nil
	}
	providerID, err := newUUIDV7String()
	if err != nil {
		return err
	}
	return s.q.UserProviderInsertSimple(ctx, db.UserProviderInsertSimpleParams{ID: providerID, UserID: userID, Issuer: issuer, Subject: subject, EmailAtProvider: email})
}

// setProviderUsername stores a provider-specific username into profile jsonb as {"username": <value>}.
func (s *Service) setProviderUsername(ctx context.Context, userID, issuer, subject, username string) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserProviderSetUsername(ctx, db.UserProviderSetUsernameParams{UserID: userID, Issuer: issuer, Subject: subject, Username: username})
}

// getProviderUsername fetches provider profile->>'username' for the given user (first match by provider).
func (s *Service) getProviderUsername(ctx context.Context, userID, provider string) (string, error) {
	if s.pg == nil {
		return "", nil
	}
	uname, err := s.q.UserProviderUsername(ctx, db.UserProviderUsernameParams{UserID: userID, ProviderSlug: &provider})
	if err != nil {
		return "", err
	}
	if uname == nil {
		return "", nil
	}
	return *uname, nil
}
