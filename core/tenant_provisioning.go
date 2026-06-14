package core

import (
	"context"
	"errors"
	"strings"
	"time"
)

// TenantProvisionRequest is the privileged/bootstrap tenant provisioning API
// for embedded hosts. It is additive/upsert by design: omitted objects are left
// alone, never removed.
type TenantProvisionRequest struct {
	Slug          string
	Issuers       []TenantProvisionIssuer
	Roles         []TenantProvisionRole
	Memberships   []TenantProvisionMembership
	ServiceTokens []TenantProvisionServiceToken
}

// TenantProvisionIssuer declares one remote_application (federation principal,
// #74) to register and bind as a member of the tenant. Slug defaults to the
// tenant slug when empty.
type TenantProvisionIssuer struct {
	Slug      string
	Issuer    string
	JWKSURI   string
	Audiences []string
	Enabled   *bool
}

// TenantProvisionRole declares or updates one tenant role.
type TenantProvisionRole struct {
	Name        string
	Permissions []string
}

// TenantProvisionMembership declares one tenant membership and role.
type TenantProvisionMembership struct {
	UserID string
	Role   string
}

// TenantProvisionServiceToken declares one generated opaque service token.
// When Output is empty, the plaintext token is returned in the result. When
// Output is non-empty and a store is supplied, existing non-empty output is
// preserved and no new token is minted.
type TenantProvisionServiceToken struct {
	Name        string
	Permissions []string
	Resources   []ServiceTokenResource
	ExpiresAt   *time.Time
	CreatedBy   string
	Output      TenantManifestServiceTokenOutput
}

// MintedTenantProvisionServiceToken contains a plaintext generated token. The
// value is returned only at creation time and should be written to a secret
// store by the caller.
type MintedTenantProvisionServiceToken struct {
	Name      string
	Metadata  ServiceToken
	Plaintext string
	Output    TenantManifestServiceTokenOutput
}

// TenantProvisionResult summarizes one additive provisioning operation.
type TenantProvisionResult struct {
	Tenant       Tenant
	Created      bool
	Issuers      int
	Roles        int
	Memberships  int
	TokensMinted int
	TokensKept   int
	MintedTokens []MintedTenantProvisionServiceToken
}

// ProvisionTenant applies privileged tenant provisioning for embedded hosts
// and deployment bootstrap jobs. Unlike public self-service registration, this
// API may create an ownerless tenant. Hosts that want a human-owned public
// tenant must use CreateTenantForUser.
func (s *Service) ProvisionTenant(ctx context.Context, req TenantProvisionRequest, store TenantManifestTokenStore) (TenantProvisionResult, error) {
	if err := s.requirePG(); err != nil {
		return TenantProvisionResult{}, err
	}
	slug := strings.ToLower(strings.TrimSpace(req.Slug))
	if err := validateTenantSlug(slug); err != nil {
		return TenantProvisionResult{}, ErrInvalidTenantManifest
	}

	var result TenantProvisionResult
	tenant, err := s.ResolveTenantBySlug(ctx, slug)
	if err != nil {
		if !errors.Is(err, ErrTenantNotFound) {
			return result, err
		}
		tenant, err = s.CreateTenant(ctx, slug)
		if err != nil {
			return result, err
		}
		result.Created = true
	}
	result.Tenant = *tenant

	for _, issuer := range req.Issuers {
		enabled := true
		if issuer.Enabled != nil {
			enabled = *issuer.Enabled
		}
		slug := strings.TrimSpace(issuer.Slug)
		if slug == "" {
			slug = tenant.Slug
		}
		ra, err := s.UpsertRemoteApplication(ctx, RemoteApplication{
			Slug:        slug,
			OwnerUserID: tenant.OwnerUserID,
			Issuer:      issuer.Issuer,
			JWKSURI:     issuer.JWKSURI,
			Audiences:   issuer.Audiences,
			Enabled:     enabled,
		})
		if err != nil {
			return result, err
		}
		// Bind the remote_application as a member of the tenant it federates into.
		if err := s.AddRemoteApplicationMember(ctx, tenant.Slug, ra.ID, "member"); err != nil {
			return result, err
		}
		result.Issuers++
	}

	for _, role := range req.Roles {
		name := strings.TrimSpace(role.Name)
		if name == "" {
			return result, ErrInvalidTenantManifest
		}
		if err := s.DefineRole(ctx, tenant.Slug, name); err != nil {
			return result, err
		}
		if err := s.SetRolePermissions(ctx, tenant.Slug, name, role.Permissions); err != nil {
			return result, err
		}
		result.Roles++
	}

	for _, membership := range req.Memberships {
		userID := strings.TrimSpace(membership.UserID)
		role := canonicalizeTenantRole(membership.Role)
		if userID == "" {
			return result, ErrInvalidTenantOwner
		}
		if role == "" {
			role = tenantMemberRole
		}
		if err := s.DefineRole(ctx, tenant.Slug, role); err != nil {
			return result, err
		}
		if err := s.AddMember(ctx, tenant.Slug, userID); err != nil {
			return result, err
		}
		if err := s.AssignRole(ctx, tenant.Slug, userID, role); err != nil {
			return result, err
		}
		result.Memberships++
	}

	for _, token := range req.ServiceTokens {
		if !token.Output.empty() {
			if store == nil {
				return result, ErrInvalidTenantManifest
			}
			existing, err := store.ReadTenantManifestToken(ctx, token.Output)
			if err != nil {
				return result, err
			}
			if strings.TrimSpace(existing) != "" {
				result.TokensKept++
				continue
			}
		}
		metadata, plaintext, err := s.MintServiceTokenWithOptions(ctx, tenant.Slug, ServiceTokenMintOptions{
			Name:        token.Name,
			Permissions: token.Permissions,
			Resources:   token.Resources,
			CreatedBy:   token.CreatedBy,
			ExpiresAt:   token.ExpiresAt,
		})
		if err != nil {
			return result, err
		}
		if !token.Output.empty() {
			if err := store.WriteTenantManifestToken(ctx, token.Output, plaintext); err != nil {
				return result, err
			}
		}
		result.TokensMinted++
		result.MintedTokens = append(result.MintedTokens, MintedTenantProvisionServiceToken{
			Name: token.Name, Metadata: metadata, Plaintext: plaintext, Output: token.Output,
		})
	}

	return result, nil
}
