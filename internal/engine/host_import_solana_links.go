package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/internal/siws"
)

type importedSolanaLinkProfile struct {
	MigrationSource     string     `json:"migration_source"`
	MigrationSourceID   string     `json:"migration_source_id"`
	MigrationSourceTime *time.Time `json:"migration_source_created_at,omitempty"`
	ImportedAt          time.Time  `json:"imported_at"`
}

// ImportSolanaLinks imports legacy wallet claims as a host operation, one
// outcome per row. It never verifies a wallet: only a successful SIWS proof
// promotes an imported claim.
func (s *Engine) ImportSolanaLinks(ctx context.Context, rows []iam.ImportSolanaLink, opts ...ops.Option) (iam.ImportSolanaLinksResult, error) {
	if err := noOptions("ImportSolanaLinks", opts); err != nil {
		return iam.ImportSolanaLinksResult{}, err
	}
	out := iam.ImportSolanaLinksResult{Rows: make([]iam.ImportSolanaLinkRow, len(rows))}
	for i, in := range rows {
		row, err := s.importUnverifiedSolanaLink(ctx, in)
		if err != nil {
			return out, fmt.Errorf("import Solana link at index %d: %w", i, err)
		}
		row.Index, row.UserID, row.Address = i, in.UserID, in.Address
		out.Rows[i] = row
		switch row.Status {
		case iam.ImportInserted:
			out.Inserted++
		case iam.ImportSkipped:
			out.Skipped++
		case iam.ImportRejected:
			out.Rejected++
		}
	}
	return out, nil
}

// importUnverifiedSolanaLink reserves a legacy Solana address for its mapped
// AuthKit user without making it a login method. Only a later successful SIWS
// proof promotes the row to verified state.
func (s *Engine) importUnverifiedSolanaLink(ctx context.Context, in iam.ImportSolanaLink) (iam.ImportSolanaLinkRow, error) {
	var out iam.ImportSolanaLinkRow
	if err := s.requirePG(); err != nil {
		return out, err
	}

	userID := strings.TrimSpace(in.UserID)
	address := strings.TrimSpace(in.Address)
	source := strings.TrimSpace(in.Source)
	sourceID := strings.TrimSpace(in.SourceID)
	if _, err := uuid.Parse(userID); err != nil {
		return iam.ImportSolanaLinkRow{Status: iam.ImportRejected, Reason: iam.ImportInvalidUserID}, nil
	}
	if err := siws.ValidateAddress(address); err != nil {
		return iam.ImportSolanaLinkRow{Status: iam.ImportRejected, Reason: iam.ImportInvalidAddress}, nil
	}
	if source == "" {
		return iam.ImportSolanaLinkRow{Status: iam.ImportRejected, Reason: iam.ImportMissingSource}, nil
	}
	if sourceID == "" {
		return iam.ImportSolanaLinkRow{Status: iam.ImportRejected, Reason: iam.ImportMissingSourceID}, nil
	}
	if _, err := s.q.UserByID(ctx, userID); err != nil {
		if err == pgx.ErrNoRows {
			return iam.ImportSolanaLinkRow{Status: iam.ImportRejected, Reason: iam.ImportMissingUser}, nil
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
		MigrationSource:     source,
		MigrationSourceID:   sourceID,
		MigrationSourceTime: sourceCreatedAt,
		ImportedAt:          importedAt,
	})
	if err != nil {
		return out, err
	}
	id, err := newUUIDV7String()
	if err != nil {
		return out, err
	}
	providerSlug := solanaProviderSlug
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
		return iam.ImportSolanaLinkRow{Status: iam.ImportInserted}, nil
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
			return iam.ImportSolanaLinkRow{Status: iam.ImportRejected, Reason: iam.ImportAddressOwnedByOtherUser}, nil
		}
		if byAddress.VerifiedAt != nil {
			return iam.ImportSolanaLinkRow{Status: iam.ImportSkipped, Reason: iam.ImportAlreadyVerified}, nil
		}
		return iam.ImportSolanaLinkRow{Status: iam.ImportSkipped, Reason: iam.ImportAlreadyImported}, nil
	}
	if addressErr != pgx.ErrNoRows {
		return out, addressErr
	}

	byUser, userErr := s.q.UserProviderByIssuerAny(ctx, db.UserProviderByIssuerAnyParams{
		UserID: userID,
		Issuer: s.solanaIssuer(),
	})
	if userErr == nil && byUser.Subject != address {
		return iam.ImportSolanaLinkRow{Status: iam.ImportRejected, Reason: iam.ImportUserHasDifferentAddress}, nil
	}
	if userErr != nil && userErr != pgx.ErrNoRows {
		return out, userErr
	}
	return iam.ImportSolanaLinkRow{Status: iam.ImportRejected, Reason: iam.ImportProviderLinkConflict}, nil
}

// verifyImportedSolanaLink promotes only the exact mapped user/address pair.
// Callers must verify the SIWS proof before invoking it.
func (s *Engine) verifyImportedSolanaLink(ctx context.Context, userID, address string) error {
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

func (s *Engine) getSolanaProviderLinkAny(ctx context.Context, address string) (userID string, verified, found bool, err error) {
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
