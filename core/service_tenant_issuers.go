package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	// ErrTenantIssuerNotFound indicates no tenant-tenant issuer matched.
	ErrTenantIssuerNotFound = errors.New("tenant_issuer_not_found")
	// ErrInvalidTenantIssuer indicates a malformed registration payload.
	ErrInvalidTenantIssuer = errors.New("invalid_tenant_issuer")
)

// TenantIssuer is a registered tenant-owned issuer. A tenant brings its own
// users that authenticate via the tenant's issuer; this record is the resource
// server side's trusted OIDC issuer registration.
type TenantIssuer struct {
	ID         string
	TenantSlug string
	Issuer     string // OIDC iss
	JWKSURI    string // OIDC jwks_uri
	Audiences  []string
	Enabled    bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// UpsertTenantIssuer registers or updates a tenant-owned OIDC issuer.
func (s *Service) UpsertTenantIssuer(ctx context.Context, in TenantIssuer) (*TenantIssuer, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	tenantSlug := strings.ToLower(strings.TrimSpace(in.TenantSlug))
	issuer := strings.TrimSpace(in.Issuer)
	jwksURI := strings.TrimSpace(in.JWKSURI)
	if tenantSlug == "" || issuer == "" || jwksURI == "" {
		return nil, ErrInvalidTenantIssuer
	}
	if err := validateTenantSlug(tenantSlug); err != nil {
		return nil, ErrInvalidTenantIssuer
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			return nil, ErrInvalidTenantIssuer
		}
		return nil, err
	}
	audiences := dedupeStrings(in.Audiences)

	var out TenantIssuer
	err = s.pg.QueryRow(ctx, `
		INSERT INTO profiles.tenant_issuers (tenant_id, issuer, jwks_uri, audiences, enabled)
		VALUES ($1::uuid, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, issuer) DO UPDATE
		  SET jwks_uri   = EXCLUDED.jwks_uri,
		      audiences  = EXCLUDED.audiences,
		      enabled    = EXCLUDED.enabled,
		      updated_at = now()
		RETURNING id::text, $6::text, issuer, jwks_uri, audiences, enabled, created_at, updated_at
	`, tenant.ID, issuer, jwksURI, audiences, in.Enabled, tenant.Slug).Scan(
		&out.ID, &out.TenantSlug, &out.Issuer, &out.JWKSURI, &out.Audiences, &out.Enabled, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// GetTenantIssuer returns a tenant issuer by OIDC issuer URL.
func (s *Service) GetTenantIssuer(ctx context.Context, issuer string) (*TenantIssuer, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, ErrInvalidTenantIssuer
	}
	var out TenantIssuer
	err := s.pg.QueryRow(ctx, `
		SELECT ti.id::text, t.slug, ti.issuer, ti.jwks_uri, ti.audiences, ti.enabled, ti.created_at, ti.updated_at
		FROM profiles.tenant_issuers ti
		JOIN profiles.tenants t ON t.id = ti.tenant_id AND t.deleted_at IS NULL
		WHERE ti.issuer = $1
		ORDER BY ti.created_at ASC
		LIMIT 1
	`, issuer).Scan(
		&out.ID, &out.TenantSlug, &out.Issuer, &out.JWKSURI, &out.Audiences, &out.Enabled, &out.CreatedAt, &out.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTenantIssuerNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListTenantIssuers returns registered tenant issuers. When activeOnly is true,
// only enabled rows are returned.
func (s *Service) ListTenantIssuers(ctx context.Context, activeOnly bool) ([]TenantIssuer, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	q := `
		SELECT ti.id::text, t.slug, ti.issuer, ti.jwks_uri, ti.audiences, ti.enabled, ti.created_at, ti.updated_at
		FROM profiles.tenant_issuers ti
		JOIN profiles.tenants t ON t.id = ti.tenant_id AND t.deleted_at IS NULL
	`
	if activeOnly {
		q += ` WHERE ti.enabled = true`
	}
	q += ` ORDER BY t.slug ASC, ti.issuer ASC`
	rows, err := s.pg.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantIssuer
	for rows.Next() {
		var ti TenantIssuer
		if err := rows.Scan(&ti.ID, &ti.TenantSlug, &ti.Issuer, &ti.JWKSURI, &ti.Audiences, &ti.Enabled, &ti.CreatedAt, &ti.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, ti)
	}
	return out, rows.Err()
}

// DeleteTenantIssuer removes a tenant issuer registration by OIDC issuer URL.
func (s *Service) DeleteTenantIssuer(ctx context.Context, issuer string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return ErrInvalidTenantIssuer
	}
	tag, err := s.pg.Exec(ctx, `DELETE FROM profiles.tenant_issuers WHERE issuer = $1`, issuer)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTenantIssuerNotFound
	}
	return nil
}
