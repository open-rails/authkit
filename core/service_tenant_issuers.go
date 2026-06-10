package core

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
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

	row, err := s.q.TenantIssuerUpsert(ctx, db.TenantIssuerUpsertParams{
		TenantID:  tenant.ID,
		Issuer:    issuer,
		JwksUri:   jwksURI,
		Audiences: audiences,
		Enabled:   in.Enabled,
	})
	if err != nil {
		return nil, err
	}
	return &TenantIssuer{
		ID:         row.ID,
		TenantSlug: tenant.Slug,
		Issuer:     row.Issuer,
		JWKSURI:    row.JwksUri,
		Audiences:  row.Audiences,
		Enabled:    row.Enabled,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}, nil
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
	row, err := s.q.TenantIssuerByIssuer(ctx, issuer)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTenantIssuerNotFound
	}
	if err != nil {
		return nil, err
	}
	return &TenantIssuer{ID: row.ID, TenantSlug: row.Slug, Issuer: row.Issuer, JWKSURI: row.JwksUri, Audiences: row.Audiences, Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}, nil
}

// ListTenantIssuers returns registered tenant issuers. When activeOnly is true,
// only enabled rows are returned.
func (s *Service) ListTenantIssuers(ctx context.Context, activeOnly bool) ([]TenantIssuer, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	var out []TenantIssuer
	if activeOnly {
		rows, err := s.q.TenantIssuersEnabled(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			out = append(out, TenantIssuer{ID: r.ID, TenantSlug: r.Slug, Issuer: r.Issuer, JWKSURI: r.JwksUri, Audiences: r.Audiences, Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
		}
		return out, nil
	}
	rows, err := s.q.TenantIssuersAll(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, TenantIssuer{ID: r.ID, TenantSlug: r.Slug, Issuer: r.Issuer, JWKSURI: r.JwksUri, Audiences: r.Audiences, Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
	}
	return out, nil
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
	n, err := s.q.TenantIssuerDelete(ctx, issuer)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrTenantIssuerNotFound
	}
	return nil
}
