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

var ErrInvalidOrgManifest = errors.New("invalid_org_manifest")

// OrgManifest is the DevOps source of truth for closed-registration AuthKit
// deployments. It declares orgs plus their trusted OIDC issuers, roles, and
// optional server-to-server API keys.
type OrgManifest struct {
	Orgs []OrgManifestOrg `json:"orgs" yaml:"orgs"`
}

type OrgManifestOrg struct {
	Slug          string                    `json:"slug" yaml:"slug"`
	Issuers       []OrgManifestIssuer       `json:"issuers" yaml:"issuers"`
	Roles         []OrgManifestRole         `json:"roles" yaml:"roles"`
	Memberships   []OrgManifestMembership   `json:"memberships" yaml:"memberships"`
	APIKeys       []OrgManifestAPIKey       `json:"api_keys" yaml:"api_keys"`
	ServiceTokens []OrgManifestServiceToken `json:"service_tokens" yaml:"service_tokens"`
}

type OrgManifestIssuer struct {
	Slug           string         `json:"slug" yaml:"slug"`
	Issuer         string         `json:"issuer" yaml:"issuer"`
	JWKSURI        string         `json:"jwks_uri" yaml:"jwks_uri"`
	Mode           string         `json:"mode" yaml:"mode"`
	PublicKeys     []RemoteAppKey `json:"public_keys" yaml:"public_keys"`
	Audiences      []string       `json:"audiences" yaml:"audiences"`
	AllowedOrigins []string       `json:"allowed_origins" yaml:"allowed_origins"`
	Role           string         `json:"role" yaml:"role"`
	Permissions    []string       `json:"permissions" yaml:"permissions"`
	Enabled        *bool          `json:"enabled" yaml:"enabled"`
}

type OrgManifestRole struct {
	Name        string   `json:"name" yaml:"name"`
	Permissions []string `json:"permissions" yaml:"permissions"`
}

type OrgManifestMembership struct {
	UserID   string `json:"user_id" yaml:"user_id"`
	UserRef  string `json:"user_ref,omitempty" yaml:"user_ref,omitempty"`
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
	Email    string `json:"email,omitempty" yaml:"email,omitempty"`
	Role     string `json:"role" yaml:"role"`
}

// OrgManifestAPIKey declares one generated opaque API key.
type OrgManifestAPIKey = OrgManifestServiceToken

type OrgManifestServiceToken struct {
	Name        string                        `json:"name" yaml:"name"`
	Permissions []string                      `json:"permissions" yaml:"permissions"`
	Resources   []ServiceTokenResource        `json:"resources" yaml:"resources"`
	ExpiresAt   *time.Time                    `json:"expires_at" yaml:"expires_at"`
	Output      OrgManifestServiceTokenOutput `json:"output" yaml:"output"`
}

// OrgManifestAPIKeyOutput names where a freshly minted API key should be
// written.
type OrgManifestAPIKeyOutput = OrgManifestServiceTokenOutput

// OrgManifestServiceTokenOutput names where a freshly minted token should
// be written. AuthKit ships a file-backed implementation; Vault/Kubernetes/etc.
// can implement OrgManifestTokenStore with the same output struct.
//
// Deprecated: use OrgManifestAPIKeyOutput for public bootstrap/config surfaces.
type OrgManifestServiceTokenOutput struct {
	File       string `json:"file" yaml:"file"`
	VaultMount string `json:"vault_mount" yaml:"vault_mount"`
	VaultPath  string `json:"vault_path" yaml:"vault_path"`
	VaultField string `json:"vault_field" yaml:"vault_field"`
}

// OrgManifestTokenStore preserves existing non-empty outputs and writes newly
// minted API-key values. The store owns the output backend.
type OrgManifestTokenStore interface {
	ReadOrgManifestToken(ctx context.Context, out OrgManifestServiceTokenOutput) (string, error)
	WriteOrgManifestToken(ctx context.Context, out OrgManifestServiceTokenOutput, token string) error
}

type OrgManifestResult struct {
	Orgs         int
	Issuers      int
	Roles        int
	Memberships  int
	TokensMinted int
	TokensKept   int
}

// ParseOrgManifestYAML parses a org manifest and rejects unknown fields.
func ParseOrgManifestYAML(raw []byte) (OrgManifest, error) {
	var manifest OrgManifest
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&manifest); err != nil {
		return OrgManifest{}, err
	}
	if len(manifest.Orgs) == 0 {
		return OrgManifest{}, ErrInvalidOrgManifest
	}
	for _, org := range manifest.Orgs {
		if _, err := org.manifestAPIKeys(); err != nil {
			return OrgManifest{}, err
		}
	}
	return manifest, nil
}

func ParseOrgManifestYAMLFile(path string) (OrgManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return OrgManifest{}, err
	}
	return ParseOrgManifestYAML(raw)
}

// ReconcileOrgManifest idempotently applies orgs, issuers, roles, and API-key
// outputs. It serializes reconciliation with a Postgres advisory
// lock so multiple replicas do not mint duplicate bootstrap tokens.
func (s *Service) ReconcileOrgManifest(ctx context.Context, manifest OrgManifest, store OrgManifestTokenStore) (OrgManifestResult, error) {
	if err := s.requirePG(); err != nil {
		return OrgManifestResult{}, err
	}
	if len(manifest.Orgs) == 0 {
		return OrgManifestResult{}, ErrInvalidOrgManifest
	}
	conn, err := s.pg.Acquire(ctx)
	if err != nil {
		return OrgManifestResult{}, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('authkit:org_manifest'))`); err != nil {
		return OrgManifestResult{}, err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext('authkit:org_manifest'))`)

	var result OrgManifestResult
	for _, org := range manifest.Orgs {
		slug := strings.ToLower(strings.TrimSpace(org.Slug))
		if slug == "" {
			return result, ErrInvalidOrgManifest
		}
		req := OrgProvisionRequest{Slug: slug}
		for _, issuer := range org.Issuers {
			req.Issuers = append(req.Issuers, OrgProvisionIssuer(issuer))
		}
		for _, role := range org.Roles {
			req.Roles = append(req.Roles, OrgProvisionRole(role))
		}
		for _, membership := range org.Memberships {
			userID, err := s.resolveOrgManifestMembershipUserID(ctx, membership)
			if err != nil {
				return result, err
			}
			membership.UserID = userID
			membership.UserRef = ""
			membership.Username = ""
			membership.Email = ""
			req.Memberships = append(req.Memberships, OrgProvisionMembership{
				UserID: membership.UserID,
				Role:   membership.Role,
			})
		}
		apiKeys, err := org.manifestAPIKeys()
		if err != nil {
			return result, err
		}
		for _, token := range apiKeys {
			if store == nil || token.Output.empty() {
				return result, ErrInvalidOrgManifest
			}
			req.APIKeys = append(req.APIKeys, OrgProvisionAPIKey{
				Name:        token.Name,
				Permissions: token.Permissions,
				Resources:   token.Resources,
				ExpiresAt:   token.ExpiresAt,
				Output:      token.Output,
			})
		}
		applied, err := s.ProvisionOrg(ctx, req, store)
		if err != nil {
			return result, err
		}
		result.Orgs++
		result.Issuers += applied.Issuers
		result.Roles += applied.Roles
		result.Memberships += applied.Memberships
		result.TokensMinted += applied.TokensMinted
		result.TokensKept += applied.TokensKept
	}
	return result, nil
}

func (o OrgManifestOrg) manifestAPIKeys() ([]OrgManifestAPIKey, error) {
	if len(o.APIKeys) > 0 && len(o.ServiceTokens) > 0 {
		return nil, ErrInvalidOrgManifest
	}
	if len(o.APIKeys) > 0 {
		return o.APIKeys, nil
	}
	return o.ServiceTokens, nil
}

func (o OrgManifestServiceTokenOutput) empty() bool {
	return strings.TrimSpace(o.File) == "" &&
		strings.TrimSpace(o.VaultMount) == "" &&
		strings.TrimSpace(o.VaultPath) == "" &&
		strings.TrimSpace(o.VaultField) == ""
}

// FileOrgManifestTokenStore writes tokens to local files. It intentionally
// refuses Vault outputs; production deployments can provide a Vault-backed
// OrgManifestTokenStore with narrower deploy-time credentials.
type FileOrgManifestTokenStore struct{}

func (FileOrgManifestTokenStore) ReadOrgManifestToken(_ context.Context, out OrgManifestServiceTokenOutput) (string, error) {
	path := strings.TrimSpace(out.File)
	if path == "" {
		return "", ErrInvalidOrgManifest
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

func (FileOrgManifestTokenStore) WriteOrgManifestToken(_ context.Context, out OrgManifestServiceTokenOutput, token string) error {
	path := strings.TrimSpace(out.File)
	if path == "" || strings.TrimSpace(token) == "" {
		return ErrInvalidOrgManifest
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.TrimSpace(token)+"\n"), 0o600)
}
