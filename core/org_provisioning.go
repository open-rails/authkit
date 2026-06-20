package core

import (
	"context"
	"errors"
	"strings"
	"time"
)

// OrgProvisionRequest is the privileged/bootstrap org provisioning API
// for embedded hosts. It is additive/upsert by design: omitted objects are left
// alone, never removed.
type OrgProvisionRequest struct {
	Slug        string
	Issuers     []OrgProvisionIssuer
	Roles       []OrgProvisionRole
	Memberships []OrgProvisionMembership
	APIKeys     []OrgProvisionAPIKey
}

// OrgProvisionIssuer declares one remote_application (federation principal,
// #74) to register and bind as a member of the org. Slug defaults to the
// org slug when empty.
type OrgProvisionIssuer struct {
	Slug       string
	Issuer     string
	JWKSURI    string
	Mode       string
	PublicKeys []RemoteAppKey
	Audiences  []string
	// AllowedOrigins is the exact browser Origin allow-list for delegated
	// browser requests signed by this issuer.
	AllowedOrigins []string
	Role           string
	Enabled        *bool
}

// OrgProvisionRole declares or updates one org role.
type OrgProvisionRole struct {
	Name        string
	Permissions []string
}

// OrgProvisionMembership declares one org membership and role.
type OrgProvisionMembership struct {
	UserID string
	Role   string
}

// OrgProvisionAPIKey declares one generated opaque API key.
// The key holds exactly ONE org role (#95): Role must name a role provisioned in
// the same org (req.Roles) or a pre-existing org role.
// When Output is empty, the plaintext token is returned in the result. When
// Output is non-empty and a store is supplied, existing non-empty output is
// preserved and no new token is minted.
type OrgProvisionAPIKey struct {
	Name      string
	Role      string
	Resources []APIKeyResource
	ExpiresAt *time.Time
	CreatedBy string
	Output    OrgManifestAPIKeyOutput
}

// MintedOrgProvisionAPIKey contains a plaintext generated API key. The
// value is returned only at creation time and should be written to a secret
// store by the caller.
type MintedOrgProvisionAPIKey struct {
	Name      string
	Metadata  APIKey
	Plaintext string
	Output    OrgManifestAPIKeyOutput
}

// OrgProvisionResult summarizes one additive provisioning operation.
type OrgProvisionResult struct {
	Org           Org
	Created       bool
	Issuers       int
	Roles         int
	Memberships   int
	APIKeysMinted int
	APIKeysKept   int
	MintedAPIKeys []MintedOrgProvisionAPIKey
}

// ProvisionOrg applies privileged org provisioning for embedded hosts
// and deployment bootstrap jobs. Unlike public self-service registration, this
// API may create an ownerless org. Hosts that want a human-owned public
// org must use CreateOrgForUser.
func (s *Service) ProvisionOrg(ctx context.Context, req OrgProvisionRequest, store OrgManifestTokenStore) (OrgProvisionResult, error) {
	if err := s.requirePG(); err != nil {
		return OrgProvisionResult{}, err
	}
	slug := strings.ToLower(strings.TrimSpace(req.Slug))
	if err := validateOrgSlug(slug); err != nil {
		return OrgProvisionResult{}, ErrInvalidOrgManifest
	}

	var result OrgProvisionResult
	org, err := s.ResolveOrgBySlug(ctx, slug)
	if err != nil {
		if !errors.Is(err, ErrOrgNotFound) {
			return result, err
		}
		org, err = s.CreateOrg(ctx, slug)
		if err != nil {
			return result, err
		}
		result.Created = true
	}
	result.Org = *org

	for _, role := range req.Roles {
		name := strings.TrimSpace(role.Name)
		if name == "" {
			return result, ErrInvalidOrgManifest
		}
		if err := s.DefineRole(ctx, org.Slug, name); err != nil {
			return result, err
		}
		if err := s.SetRolePermissions(ctx, org.Slug, name, role.Permissions); err != nil {
			return result, err
		}
		result.Roles++
	}

	for _, issuer := range req.Issuers {
		enabled := true
		if issuer.Enabled != nil {
			enabled = *issuer.Enabled
		}
		slug := strings.TrimSpace(issuer.Slug)
		if slug == "" {
			slug = org.Slug
		}
		ra, err := s.UpsertRemoteApplication(ctx, RemoteApplication{
			Slug:           slug,
			OrgID:          org.ID, // #77: each issuer belongs to exactly one org
			Issuer:         issuer.Issuer,
			JWKSURI:        issuer.JWKSURI,
			Mode:           issuer.Mode,
			PublicKeys:     issuer.PublicKeys,
			Audiences:      issuer.Audiences,
			AllowedOrigins: issuer.AllowedOrigins,
			Enabled:        enabled,
		})
		if err != nil {
			return result, err
		}
		role := strings.TrimSpace(issuer.Role)
		if role == "" {
			role = orgMemberRole
		}
		if err := s.AddRemoteApplicationMember(ctx, org.Slug, ra.ID, role); err != nil {
			return result, err
		}
		result.Issuers++
	}

	for _, membership := range req.Memberships {
		userID := strings.TrimSpace(membership.UserID)
		role := canonicalizeOrgRole(membership.Role)
		if userID == "" {
			return result, ErrInvalidOrgOwner
		}
		if role == "" {
			role = orgMemberRole
		}
		if err := s.DefineRole(ctx, org.Slug, role); err != nil {
			return result, err
		}
		if err := s.AddMember(ctx, org.Slug, userID); err != nil {
			return result, err
		}
		if err := s.AssignRole(ctx, org.Slug, userID, role); err != nil {
			return result, err
		}
		result.Memberships++
	}

	apiKeys, err := req.apiKeys()
	if err != nil {
		return result, err
	}
	for _, token := range apiKeys {
		if !token.Output.empty() {
			if store == nil {
				return result, ErrInvalidOrgManifest
			}
			existing, err := store.ReadOrgManifestToken(ctx, token.Output)
			if err != nil {
				return result, err
			}
			if strings.TrimSpace(existing) != "" {
				result.APIKeysKept++
				continue
			}
		}
		metadata, plaintext, err := s.MintAPIKeyWithOptions(ctx, org.Slug, APIKeyMintOptions{
			Name:      token.Name,
			Role:      token.Role,
			Resources: token.Resources,
			CreatedBy: token.CreatedBy,
			ExpiresAt: token.ExpiresAt,
		})
		if err != nil {
			return result, err
		}
		if !token.Output.empty() {
			if err := store.WriteOrgManifestToken(ctx, token.Output, plaintext); err != nil {
				return result, err
			}
		}
		result.APIKeysMinted++
		result.MintedAPIKeys = append(result.MintedAPIKeys, MintedOrgProvisionAPIKey{
			Name: token.Name, Metadata: metadata, Plaintext: plaintext, Output: token.Output,
		})
	}

	return result, nil
}

func (r OrgProvisionRequest) apiKeys() ([]OrgProvisionAPIKey, error) {
	return r.APIKeys, nil
}
