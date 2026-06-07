package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var ErrInvalidTenantManifest = errors.New("invalid_tenant_manifest")

// TenantManifest is the DevOps source of truth for closed-registration AuthKit
// deployments. It declares tenants plus their trusted OIDC issuers, roles, and
// optional server-to-server service tokens.
type TenantManifest struct {
	Tenants []TenantManifestTenant `json:"tenants" yaml:"tenants"`
}

type TenantManifestTenant struct {
	Slug          string                       `json:"slug" yaml:"slug"`
	Issuers       []TenantManifestIssuer       `json:"issuers" yaml:"issuers"`
	Roles         []TenantManifestRole         `json:"roles" yaml:"roles"`
	Memberships   []TenantManifestMembership   `json:"memberships" yaml:"memberships"`
	ServiceTokens []TenantManifestServiceToken `json:"service_tokens" yaml:"service_tokens"`
}

type TenantManifestIssuer struct {
	Issuer    string   `json:"issuer" yaml:"issuer"`
	JWKSURI   string   `json:"jwks_uri" yaml:"jwks_uri"`
	Audiences []string `json:"audiences" yaml:"audiences"`
	Enabled   *bool    `json:"enabled" yaml:"enabled"`
}

type TenantManifestRole struct {
	Name        string   `json:"name" yaml:"name"`
	Permissions []string `json:"permissions" yaml:"permissions"`
}

type TenantManifestMembership struct {
	UserID string `json:"user_id" yaml:"user_id"`
	Role   string `json:"role" yaml:"role"`
}

type TenantManifestServiceToken struct {
	Name        string                           `json:"name" yaml:"name"`
	Permissions []string                         `json:"permissions" yaml:"permissions"`
	Resources   []ServiceTokenResource           `json:"resources" yaml:"resources"`
	ExpiresAt   *time.Time                       `json:"expires_at" yaml:"expires_at"`
	Output      TenantManifestServiceTokenOutput `json:"output" yaml:"output"`
}

// TenantManifestServiceTokenOutput names where a freshly minted token should
// be written. AuthKit ships a file-backed implementation; Vault/Kubernetes/etc.
// can implement TenantManifestTokenStore with the same output struct.
type TenantManifestServiceTokenOutput struct {
	File       string `json:"file" yaml:"file"`
	VaultMount string `json:"vault_mount" yaml:"vault_mount"`
	VaultPath  string `json:"vault_path" yaml:"vault_path"`
	VaultField string `json:"vault_field" yaml:"vault_field"`
}

// TenantManifestTokenStore preserves existing non-empty outputs and writes
// newly minted service-token values. The store owns the output backend.
type TenantManifestTokenStore interface {
	ReadTenantManifestToken(ctx context.Context, out TenantManifestServiceTokenOutput) (string, error)
	WriteTenantManifestToken(ctx context.Context, out TenantManifestServiceTokenOutput, token string) error
}

type TenantManifestResult struct {
	Tenants      int
	Issuers      int
	Roles        int
	Memberships  int
	TokensMinted int
	TokensKept   int
}

// ParseTenantManifestYAML parses a tenant manifest and rejects unknown fields.
func ParseTenantManifestYAML(raw []byte) (TenantManifest, error) {
	var manifest TenantManifest
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&manifest); err != nil {
		return TenantManifest{}, err
	}
	if len(manifest.Tenants) == 0 {
		return TenantManifest{}, ErrInvalidTenantManifest
	}
	return manifest, nil
}

func ParseTenantManifestYAMLFile(path string) (TenantManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return TenantManifest{}, err
	}
	return ParseTenantManifestYAML(raw)
}

// ReconcileTenantManifest idempotently applies tenants, issuers, roles, and
// service-token outputs. It serializes reconciliation with a Postgres advisory
// lock so multiple replicas do not mint duplicate bootstrap tokens.
func (s *Service) ReconcileTenantManifest(ctx context.Context, manifest TenantManifest, store TenantManifestTokenStore) (TenantManifestResult, error) {
	if err := s.requirePG(); err != nil {
		return TenantManifestResult{}, err
	}
	if len(manifest.Tenants) == 0 {
		return TenantManifestResult{}, ErrInvalidTenantManifest
	}
	conn, err := s.pg.Acquire(ctx)
	if err != nil {
		return TenantManifestResult{}, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('authkit:tenant_manifest'))`); err != nil {
		return TenantManifestResult{}, err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext('authkit:tenant_manifest'))`)

	var result TenantManifestResult
	for _, tenant := range manifest.Tenants {
		slug := strings.ToLower(strings.TrimSpace(tenant.Slug))
		if slug == "" {
			return result, ErrInvalidTenantManifest
		}
		req := TenantProvisionRequest{Slug: slug}
		for _, issuer := range tenant.Issuers {
			req.Issuers = append(req.Issuers, TenantProvisionIssuer(issuer))
		}
		for _, role := range tenant.Roles {
			req.Roles = append(req.Roles, TenantProvisionRole(role))
		}
		for _, membership := range tenant.Memberships {
			req.Memberships = append(req.Memberships, TenantProvisionMembership(membership))
		}
		for _, token := range tenant.ServiceTokens {
			if store == nil || token.Output.empty() {
				return result, ErrInvalidTenantManifest
			}
			req.ServiceTokens = append(req.ServiceTokens, TenantProvisionServiceToken{
				Name:        token.Name,
				Permissions: token.Permissions,
				Resources:   token.Resources,
				ExpiresAt:   token.ExpiresAt,
				Output:      token.Output,
			})
		}
		applied, err := s.ProvisionTenant(ctx, req, store)
		if err != nil {
			return result, err
		}
		result.Tenants++
		result.Issuers += applied.Issuers
		result.Roles += applied.Roles
		result.Memberships += applied.Memberships
		result.TokensMinted += applied.TokensMinted
		result.TokensKept += applied.TokensKept
	}
	return result, nil
}

func (o TenantManifestServiceTokenOutput) empty() bool {
	return strings.TrimSpace(o.File) == "" &&
		strings.TrimSpace(o.VaultMount) == "" &&
		strings.TrimSpace(o.VaultPath) == "" &&
		strings.TrimSpace(o.VaultField) == ""
}

// FileTenantManifestTokenStore writes tokens to local files. It intentionally
// refuses Vault outputs; production deployments can provide a Vault-backed
// TenantManifestTokenStore with narrower deploy-time credentials.
type FileTenantManifestTokenStore struct{}

func (FileTenantManifestTokenStore) ReadTenantManifestToken(_ context.Context, out TenantManifestServiceTokenOutput) (string, error) {
	path := strings.TrimSpace(out.File)
	if path == "" {
		return "", ErrInvalidTenantManifest
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func (FileTenantManifestTokenStore) WriteTenantManifestToken(_ context.Context, out TenantManifestServiceTokenOutput, token string) error {
	path := strings.TrimSpace(out.File)
	if path == "" || strings.TrimSpace(token) == "" {
		return ErrInvalidTenantManifest
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.TrimSpace(token)+"\n"), 0o600)
}
