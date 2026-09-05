package embedded

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/siws"
)

type ImportUnverifiedSolanaLinkStatus = authkit.ImportUnverifiedSolanaLinkStatus

const (
	ImportUnverifiedSolanaLinkInserted = authkit.ImportUnverifiedSolanaLinkInserted
	ImportUnverifiedSolanaLinkSkipped  = authkit.ImportUnverifiedSolanaLinkSkipped
	ImportUnverifiedSolanaLinkRejected = authkit.ImportUnverifiedSolanaLinkRejected
)

type ImportUnverifiedSolanaLinkInput = authkit.ImportUnverifiedSolanaLinkInput
type ImportUnverifiedSolanaLinkResult = authkit.ImportUnverifiedSolanaLinkResult
type ImportUnverifiedSolanaLinksResult = authkit.ImportUnverifiedSolanaLinksResult

type importedSolanaLinkProfile struct {
	MigrationSource      string     `json:"migration_source"`
	MigrationSourceID    string     `json:"migration_source_id"`
	MigrationSourceTime  *time.Time `json:"migration_source_created_at,omitempty"`
	ImportedAt           time.Time  `json:"imported_at"`
	VerificationRequired bool       `json:"verification_required"`
}

// ImportUnverifiedSolanaLinks imports legacy wallet claims with one outcome per
// input row. It never verifies a wallet: only a successful SIWS proof may
// promote an imported claim. Migration tooling only; runtime request handlers
// must use the normal proof-aware Solana link flow.
func (s *Client) ImportUnverifiedSolanaLinks(ctx context.Context, inputs []ImportUnverifiedSolanaLinkInput) (ImportUnverifiedSolanaLinksResult, error) {
	out := ImportUnverifiedSolanaLinksResult{
		Results: make([]ImportUnverifiedSolanaLinkResult, len(inputs)),
	}
	for i, in := range inputs {
		result, err := s.importUnverifiedSolanaLink(ctx, in)
		if err != nil {
			return out, fmt.Errorf("import unverified Solana link at index %d: %w", i, err)
		}
		result.Index = i
		result.UserID = in.UserID
		result.Address = in.Address
		out.Results[i] = result
		switch result.Status {
		case ImportUnverifiedSolanaLinkInserted:
			out.Inserted++
		case ImportUnverifiedSolanaLinkSkipped:
			out.Skipped++
		case ImportUnverifiedSolanaLinkRejected:
			out.Rejected++
		}
	}
	return out, nil
}

// importUnverifiedSolanaLink reserves a legacy Solana address for its mapped
// AuthKit user without making it a login method. Only a later successful SIWS
// proof promotes the row to verified state.
func (s *Client) importUnverifiedSolanaLink(ctx context.Context, in ImportUnverifiedSolanaLinkInput) (ImportUnverifiedSolanaLinkResult, error) {
	var out ImportUnverifiedSolanaLinkResult
	if err := s.requirePG(); err != nil {
		return out, err
	}

	userID := strings.TrimSpace(in.UserID)
	address := strings.TrimSpace(in.Address)
	source := strings.TrimSpace(in.Source)
	sourceID := strings.TrimSpace(in.SourceID)
	if _, err := uuid.Parse(userID); err != nil {
		return ImportUnverifiedSolanaLinkResult{Status: ImportUnverifiedSolanaLinkRejected, Reason: "invalid_user_id"}, nil
	}
	if err := siws.ValidateAddress(address); err != nil {
		return ImportUnverifiedSolanaLinkResult{Status: ImportUnverifiedSolanaLinkRejected, Reason: "invalid_address"}, nil
	}
	if source == "" {
		return ImportUnverifiedSolanaLinkResult{Status: ImportUnverifiedSolanaLinkRejected, Reason: "missing_source"}, nil
	}
	if sourceID == "" {
		return ImportUnverifiedSolanaLinkResult{Status: ImportUnverifiedSolanaLinkRejected, Reason: "missing_source_id"}, nil
	}
	if _, err := s.q.UserByID(ctx, userID); err != nil {
		if err == pgx.ErrNoRows {
			return ImportUnverifiedSolanaLinkResult{Status: ImportUnverifiedSolanaLinkRejected, Reason: "missing_user"}, nil
		}
		return out, err
	}

	importedAt := time.Now().UTC()
	createdAt := importedAt
	var sourceCreatedAt *time.Time
	if in.SourceCreatedAt != nil && !in.SourceCreatedAt.IsZero() {
		normalized := in.SourceCreatedAt.UTC()
		sourceCreatedAt = &normalized
		createdAt = normalized
	}
	profile, err := json.Marshal(importedSolanaLinkProfile{
		MigrationSource:      source,
		MigrationSourceID:    sourceID,
		MigrationSourceTime:  sourceCreatedAt,
		ImportedAt:           importedAt,
		VerificationRequired: true,
	})
	if err != nil {
		return out, err
	}
	id, err := newUUIDV7String()
	if err != nil {
		return out, err
	}
	providerSlug := SolanaProviderSlug
	_, err = s.q.UserProviderImportUnverified(ctx, db.UserProviderImportUnverifiedParams{
		ID:           id,
		UserID:       userID,
		Issuer:       s.solanaIssuer(),
		ProviderSlug: &providerSlug,
		Subject:      address,
		Profile:      profile,
		CreatedAt:    createdAt,
	})
	if err == nil {
		return ImportUnverifiedSolanaLinkResult{Status: ImportUnverifiedSolanaLinkInserted}, nil
	}
	if err != pgx.ErrNoRows {
		return out, fmt.Errorf("import unverified Solana link: %w", err)
	}

	byAddress, addressErr := s.q.ProviderLinkByIssuerAny(ctx, db.ProviderLinkByIssuerAnyParams{
		Issuer:  s.solanaIssuer(),
		Subject: address,
	})
	if addressErr == nil {
		if byAddress.UserID != userID {
			return ImportUnverifiedSolanaLinkResult{Status: ImportUnverifiedSolanaLinkRejected, Reason: "address_owned_by_other_user"}, nil
		}
		if byAddress.VerifiedAt != nil {
			return ImportUnverifiedSolanaLinkResult{Status: ImportUnverifiedSolanaLinkSkipped, Reason: "already_verified"}, nil
		}
		return ImportUnverifiedSolanaLinkResult{Status: ImportUnverifiedSolanaLinkSkipped, Reason: "already_imported"}, nil
	}
	if addressErr != pgx.ErrNoRows {
		return out, addressErr
	}

	byUser, userErr := s.q.UserProviderByIssuerAny(ctx, db.UserProviderByIssuerAnyParams{
		UserID: userID,
		Issuer: s.solanaIssuer(),
	})
	if userErr == nil && byUser.Subject != address {
		return ImportUnverifiedSolanaLinkResult{Status: ImportUnverifiedSolanaLinkRejected, Reason: "user_has_different_address"}, nil
	}
	if userErr != nil && userErr != pgx.ErrNoRows {
		return out, userErr
	}
	return ImportUnverifiedSolanaLinkResult{Status: ImportUnverifiedSolanaLinkRejected, Reason: "provider_link_conflict"}, nil
}

// verifyImportedSolanaLink promotes only the exact mapped user/address pair.
// Callers must verify the SIWS proof before invoking it.
func (s *Client) verifyImportedSolanaLink(ctx context.Context, userID, address string) error {
	_, err := s.q.UserProviderVerifyImported(ctx, db.UserProviderVerifyImportedParams{
		UserID:  userID,
		Issuer:  s.solanaIssuer(),
		Subject: address,
	})
	if err != nil {
		return err
	}
	s.maybeResolveSolanaSNSAfterLink(ctx, userID, address)
	return nil
}

func (s *Client) getSolanaProviderLinkAny(ctx context.Context, address string) (userID string, verified, found bool, err error) {
	row, err := s.q.ProviderLinkByIssuerAny(ctx, db.ProviderLinkByIssuerAnyParams{
		Issuer:  s.solanaIssuer(),
		Subject: strings.TrimSpace(address),
	})
	if err == pgx.ErrNoRows {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	return row.UserID, row.VerifiedAt != nil, true, nil
}
