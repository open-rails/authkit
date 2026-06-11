package core

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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

// Tenant-issuer trust modes (#465). Exactly one trust source per issuer,
// never both:
//
//	jwks   — preferred: keys are fetched + refreshed from JWKSURI; rotation is
//	         publishing a new kid at the same URL (no API call, no humans).
//	static — authorized_keys-style: a human-managed list of public-key PEMs
//	         for services without a JWKS endpoint; manual rotation by design.
const (
	TenantIssuerModeJWKS   = "jwks"
	TenantIssuerModeStatic = "static"
)

// TenantIssuerKey is one entry of a static-mode issuer's human-managed key
// list (stored as jsonb; edited like an authorized_keys file).
type TenantIssuerKey struct {
	KID          string `json:"kid,omitempty"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// NormalizeTenantIssuerTrustSource validates the mutually-exclusive trust
// source of a registration and returns the normalized mode. Empty mode is
// inferred: a key list means static, otherwise jwks. It is the single
// validation gate for BOTH the tenant-issuers route and registration-time
// binding, so the XOR rule cannot be bypassed.
func NormalizeTenantIssuerTrustSource(jwksURI string, mode string, keys []TenantIssuerKey) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	jwksURI = strings.TrimSpace(jwksURI)
	if mode == "" {
		if len(keys) > 0 {
			mode = TenantIssuerModeStatic
		} else {
			mode = TenantIssuerModeJWKS
		}
	}
	switch mode {
	case TenantIssuerModeJWKS:
		if jwksURI == "" {
			return "", fmt.Errorf("%w: jwks mode requires jwks_uri", ErrInvalidTenantIssuer)
		}
		if len(keys) > 0 {
			return "", fmt.Errorf("%w: jwks_uri and public_keys are mutually exclusive — register one trust source, never both", ErrInvalidTenantIssuer)
		}
	case TenantIssuerModeStatic:
		if len(keys) == 0 {
			return "", fmt.Errorf("%w: static mode requires a non-empty public_keys list", ErrInvalidTenantIssuer)
		}
		if jwksURI != "" {
			return "", fmt.Errorf("%w: jwks_uri and public_keys are mutually exclusive — register one trust source, never both", ErrInvalidTenantIssuer)
		}
		for i, k := range keys {
			if err := validatePublicKeyPEM(k.PublicKeyPEM); err != nil {
				return "", fmt.Errorf("%w: public_keys[%d]: %v", ErrInvalidTenantIssuer, i, err)
			}
		}
	default:
		return "", fmt.Errorf("%w: unknown mode %q (want jwks|static)", ErrInvalidTenantIssuer, mode)
	}
	return mode, nil
}

// validatePublicKeyPEM accepts PKIX ("PUBLIC KEY") and PKCS1 ("RSA PUBLIC
// KEY") blocks — same shapes the verifier's static-key path parses.
func validatePublicKeyPEM(raw string) error {
	block, _ := pem.Decode([]byte(strings.TrimSpace(raw)))
	if block == nil {
		return errors.New("not a PEM block")
	}
	switch block.Type {
	case "PUBLIC KEY":
		if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			return fmt.Errorf("invalid PKIX public key: %v", err)
		}
	case "RSA PUBLIC KEY":
		if _, err := x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
			return fmt.Errorf("invalid PKCS1 public key: %v", err)
		}
	default:
		return fmt.Errorf("unsupported PEM block %q", block.Type)
	}
	return nil
}

func decodeTenantIssuerKeys(raw []byte) []TenantIssuerKey {
	if len(raw) == 0 {
		return nil
	}
	var keys []TenantIssuerKey
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil
	}
	return keys
}

// TenantIssuer is a registered tenant-owned issuer. A tenant brings its own
// users that authenticate via the tenant's issuer; this record is the resource
// server side's trusted OIDC issuer registration.
type TenantIssuer struct {
	ID         string
	TenantSlug string
	Issuer     string // OIDC iss
	JWKSURI    string // OIDC jwks_uri (jwks mode only)
	// Mode is the trust source: TenantIssuerModeJWKS (fetch from JWKSURI) XOR
	// TenantIssuerModeStatic (human-managed PublicKeys list). Never both.
	Mode string
	// PublicKeys is the static-mode key list (empty in jwks mode).
	PublicKeys []TenantIssuerKey
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
	if tenantSlug == "" || issuer == "" {
		return nil, ErrInvalidTenantIssuer
	}
	mode, err := NormalizeTenantIssuerTrustSource(jwksURI, in.Mode, in.PublicKeys)
	if err != nil {
		return nil, err
	}
	var keysJSON []byte
	if mode == TenantIssuerModeStatic {
		keysJSON, err = json.Marshal(in.PublicKeys)
		if err != nil {
			return nil, ErrInvalidTenantIssuer
		}
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
		TenantID:   tenant.ID,
		Issuer:     issuer,
		JwksUri:    jwksURI,
		Audiences:  audiences,
		Enabled:    in.Enabled,
		Mode:       mode,
		PublicKeys: keysJSON,
	})
	if err != nil {
		return nil, err
	}
	return &TenantIssuer{
		ID:         row.ID,
		TenantSlug: tenant.Slug,
		Issuer:     row.Issuer,
		JWKSURI:    row.JwksUri,
		Mode:       row.Mode,
		PublicKeys: decodeTenantIssuerKeys(row.PublicKeys),
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
	return &TenantIssuer{ID: row.ID, TenantSlug: row.Slug, Issuer: row.Issuer, JWKSURI: row.JwksUri, Mode: row.Mode, PublicKeys: decodeTenantIssuerKeys(row.PublicKeys), Audiences: row.Audiences, Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}, nil
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
			out = append(out, TenantIssuer{ID: r.ID, TenantSlug: r.Slug, Issuer: r.Issuer, JWKSURI: r.JwksUri, Mode: r.Mode, PublicKeys: decodeTenantIssuerKeys(r.PublicKeys), Audiences: r.Audiences, Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
		}
		return out, nil
	}
	rows, err := s.q.TenantIssuersAll(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, TenantIssuer{ID: r.ID, TenantSlug: r.Slug, Issuer: r.Issuer, JWKSURI: r.JwksUri, Mode: r.Mode, PublicKeys: decodeTenantIssuerKeys(r.PublicKeys), Audiences: r.Audiences, Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
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
