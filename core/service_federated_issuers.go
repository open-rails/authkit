package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	// ErrFederatedIssuerNotFound indicates no federated-org issuer matched.
	ErrFederatedIssuerNotFound = errors.New("federated_issuer_not_found")
	// ErrInvalidFederatedIssuer indicates a malformed registration payload.
	ErrInvalidFederatedIssuer = errors.New("invalid_federated_issuer")
)

// FederatedOrgIssuer is a registered federated-org issuer. A federated org
// brings its own users that authenticate via the org's OWN issuer (not local
// passwords); this record is the resource-server side's record of a trusted
// issuer it will accept delegated tokens from.
type FederatedOrgIssuer struct {
	ID        string
	OrgSlug   string
	IssuerID  string // the `iss` URL of the federated platform
	JWKSURL   string
	Status    string // "active" | "inactive"
	CreatedAt time.Time
	UpdatedAt time.Time
}

const (
	federatedIssuerStatusActive   = "active"
	federatedIssuerStatusInactive = "inactive"
)

func normalizeFederatedStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case federatedIssuerStatusInactive:
		return federatedIssuerStatusInactive
	default:
		return federatedIssuerStatusActive
	}
}

// UpsertFederatedOrgIssuer registers (or updates) a federated-org issuer. The
// registration is keyed on issuer_id (the `iss` URL): re-registering the same
// issuer updates its org slug, JWKS URL, and status.
func (s *Service) UpsertFederatedOrgIssuer(ctx context.Context, in FederatedOrgIssuer) (*FederatedOrgIssuer, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	orgSlug := strings.ToLower(strings.TrimSpace(in.OrgSlug))
	issuerID := strings.TrimSpace(in.IssuerID)
	jwksURL := strings.TrimSpace(in.JWKSURL)
	if orgSlug == "" || issuerID == "" || jwksURL == "" {
		return nil, ErrInvalidFederatedIssuer
	}
	if err := validateOrgSlug(orgSlug); err != nil {
		return nil, ErrInvalidFederatedIssuer
	}
	status := normalizeFederatedStatus(in.Status)

	var out FederatedOrgIssuer
	err := s.pg.QueryRow(ctx, `
		INSERT INTO profiles.federated_org_issuers (org_slug, issuer_id, jwks_url, status)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (issuer_id) DO UPDATE
		  SET org_slug   = EXCLUDED.org_slug,
		      jwks_url   = EXCLUDED.jwks_url,
		      status     = EXCLUDED.status,
		      updated_at = now()
		RETURNING id::text, org_slug, issuer_id, jwks_url, status, created_at, updated_at
	`, orgSlug, issuerID, jwksURL, status).Scan(
		&out.ID, &out.OrgSlug, &out.IssuerID, &out.JWKSURL, &out.Status, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// GetFederatedOrgIssuer returns a federated-org issuer by its issuer_id.
func (s *Service) GetFederatedOrgIssuer(ctx context.Context, issuerID string) (*FederatedOrgIssuer, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	issuerID = strings.TrimSpace(issuerID)
	if issuerID == "" {
		return nil, ErrInvalidFederatedIssuer
	}
	var out FederatedOrgIssuer
	err := s.pg.QueryRow(ctx, `
		SELECT id::text, org_slug, issuer_id, jwks_url, status, created_at, updated_at
		FROM profiles.federated_org_issuers
		WHERE issuer_id = $1
	`, issuerID).Scan(
		&out.ID, &out.OrgSlug, &out.IssuerID, &out.JWKSURL, &out.Status, &out.CreatedAt, &out.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrFederatedIssuerNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListFederatedOrgIssuers returns registered federated-org issuers. When
// activeOnly is true, only `active` rows are returned (the set the Verifier
// should trust).
func (s *Service) ListFederatedOrgIssuers(ctx context.Context, activeOnly bool) ([]FederatedOrgIssuer, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	q := `
		SELECT id::text, org_slug, issuer_id, jwks_url, status, created_at, updated_at
		FROM profiles.federated_org_issuers
	`
	if activeOnly {
		q += ` WHERE status = 'active'`
	}
	q += ` ORDER BY org_slug ASC, issuer_id ASC`
	rows, err := s.pg.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FederatedOrgIssuer
	for rows.Next() {
		var fi FederatedOrgIssuer
		if err := rows.Scan(&fi.ID, &fi.OrgSlug, &fi.IssuerID, &fi.JWKSURL, &fi.Status, &fi.CreatedAt, &fi.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, fi)
	}
	return out, rows.Err()
}

// DeleteFederatedOrgIssuer removes a federated-org issuer registration by its
// issuer_id. Returns ErrFederatedIssuerNotFound when nothing was deleted.
func (s *Service) DeleteFederatedOrgIssuer(ctx context.Context, issuerID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	issuerID = strings.TrimSpace(issuerID)
	if issuerID == "" {
		return ErrInvalidFederatedIssuer
	}
	tag, err := s.pg.Exec(ctx, `DELETE FROM profiles.federated_org_issuers WHERE issuer_id = $1`, issuerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrFederatedIssuerNotFound
	}
	return nil
}
