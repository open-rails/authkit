package authhttp

import (
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

// Service Token (service token) management endpoints. A service token carries a set of
// app-defined PERMISSIONS (opaque to authkit). All three endpoints are gated by
// the base permission tenant:service_tokens:manage (owner holds `*`; a platform global
// admin bypasses). Minting validates the requested permissions against the
// catalog AND the caller's own effective permissions (no-escalation), and bars
// wildcards + the write/mint reserved `tenant:` management permissions from service tokens
// (a service token does machine work, not tenant management). Read-only tenant:read IS
// service token-grantable (escalation-harmless, for monitoring/audit automation). A
// service principal (a service token) has no UserID,
// so it can never reach these handlers — a service token can never mint/list/revoke service tokens.

// accessTokenView is the non-secret JSON shape returned for a service token. The secret
// is only ever present in the create response's top-level `token` field.
type accessTokenView struct {
	ID          string                      `json:"id"`
	KeyID       string                      `json:"key_id"`
	Name        string                      `json:"name"`
	Permissions []string                    `json:"permissions"`
	Resources   []core.ServiceTokenResource `json:"resources"`
	CreatedBy   string                      `json:"created_by,omitempty"`
	CreatedAt   string                      `json:"created_at"`
	LastUsedAt  string                      `json:"last_used_at,omitempty"`
	ExpiresAt   string                      `json:"expires_at,omitempty"`
	RevokedAt   string                      `json:"revoked_at,omitempty"`
}

func rfc3339Ptr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func toAccessTokenView(t core.ServiceToken) accessTokenView {
	perms := t.Permissions
	if perms == nil {
		perms = []string{}
	}
	resources := t.Resources
	if resources == nil {
		resources = []core.ServiceTokenResource{}
	}
	return accessTokenView{
		ID:          t.ID,
		KeyID:       t.KeyID,
		Name:        t.Name,
		Permissions: perms,
		Resources:   resources,
		CreatedBy:   t.CreatedBy,
		CreatedAt:   t.CreatedAt.UTC().Format(time.RFC3339),
		LastUsedAt:  rfc3339Ptr(t.LastUsedAt),
		ExpiresAt:   rfc3339Ptr(t.ExpiresAt),
		RevokedAt:   rfc3339Ptr(t.RevokedAt),
	}
}

// cleanStrings trims, drops empties, and de-duplicates while preserving order.
func cleanStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// orgAccessTokenManageGate resolves the tenant and confirms the caller holds
// tenant:service_tokens:manage (list/revoke). Owner holds `*`; a global admin bypasses.
func (s *Service) tenantAccessTokenManageGate(w http.ResponseWriter, r *http.Request, claims Claims, tenantSlug string) (canonical string, ok bool) {
	return s.requireTenantPermissionGin(w, r, claims, tenantSlug, core.PermTenantTokensManage)
}

func (s *Service) handleServiceTokensPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	// A service principal (service token) has no UserID; this both authenticates a human
	// admin and structurally prevents a service token from minting another service token.
	if !ok || strings.TrimSpace(claims.UserID) == "" || claims.IsService() {
		unauthorized(w, "unauthorized")
		return
	}
	tenantSlug := strings.TrimSpace(r.PathValue("tenant"))
	if tenantSlug == "" {
		badRequest(w, "invalid_request")
		return
	}

	var body struct {
		Name        string                      `json:"name"`
		Permissions []string                    `json:"permissions"`
		Resources   []core.ServiceTokenResource `json:"resources"`
		ExpiresAt   string                      `json:"expires_at"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		badRequest(w, "missing_name")
		return
	}

	var expiresAt *time.Time
	if ts := strings.TrimSpace(body.ExpiresAt); ts != "" {
		parsed, err := time.Parse(time.RFC3339, ts)
		if err != nil || !parsed.After(time.Now().UTC()) {
			badRequest(w, "invalid_expiry")
			return
		}
		expiresAt = &parsed
	}

	permissions := cleanStrings(body.Permissions)
	resources := body.Resources

	// Authorize the mint + the permission grant.
	canonical, ok := s.authorizeServiceTokenMint(w, r, claims, tenantSlug, permissions)
	if !ok {
		return
	}
	if err := s.svc.AuthorizeServiceTokenResources(r.Context(), core.ResourceScopeAuthorizationRequest{
		TenantSlug:       canonical,
		ActorUserID:      claims.UserID,
		Permissions:      permissions,
		Resources:        resources,
		ActorGlobalAdmin: claimsHasGlobalAdmin(claims),
	}); err != nil {
		switch err.Error() {
		case "invalid_resource":
			badRequest(w, "invalid_resource")
		case "duplicate_resource":
			badRequest(w, "duplicate_resource")
		default:
			sendErrData(w, http.StatusForbidden, "resource_scope_denied", map[string]any{})
		}
		return
	}

	tok, plaintext, err := s.svc.MintServiceTokenWithOptions(r.Context(), canonical, core.ServiceTokenMintOptions{
		Name:        body.Name,
		Permissions: permissions,
		Resources:   resources,
		CreatedBy:   claims.UserID,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		switch err.Error() {
		case "invalid_expiry":
			badRequest(w, "invalid_expiry")
		case "missing_name":
			badRequest(w, "missing_name")
		case "invalid_resource":
			badRequest(w, "invalid_resource")
		case "duplicate_resource":
			badRequest(w, "duplicate_resource")
		default:
			serverErr(w, "access_token_create_failed")
		}
		return
	}

	view := toAccessTokenView(tok)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          view.ID,
		"key_id":      view.KeyID,
		"name":        view.Name,
		"permissions": view.Permissions,
		"resources":   view.Resources,
		"created_at":  view.CreatedAt,
		"expires_at":  view.ExpiresAt,
		// Shown ONCE — never retrievable again.
		"token": plaintext,
	})
}

// authorizeServiceTokenMint gates minting on tenant:service_tokens:manage and validates the
// requested permissions: they must be concrete catalog permissions the caller
// itself holds (no-escalation) — never wildcards/exclusions or reserved `tenant:`
// management permissions (a service token does machine work, not tenant management).
func (s *Service) authorizeServiceTokenMint(w http.ResponseWriter, r *http.Request, claims Claims, tenantSlug string, permissions []string) (canonical string, ok bool) {
	var notGrantable []string
	for _, p := range permissions {
		if p == core.PermWildcard || strings.HasPrefix(p, "!") || (core.IsReservedPermission(p) && !core.IsServiceTokenGrantableReservedPermission(p)) {
			notGrantable = append(notGrantable, p)
		}
	}
	if len(notGrantable) > 0 {
		sendErrData(w, http.StatusForbidden, "permission_not_grantable_to_service_token", map[string]any{"offending_permissions": notGrantable})
		return "", false
	}
	canonical, gateOK := s.requireTenantPermissionGin(w, r, claims, tenantSlug, core.PermTenantTokensManage)
	if !gateOK {
		return "", false
	}
	unknown, offending, err := s.svc.ValidateGrant(r.Context(), canonical, claims.UserID, permissions, claimsHasGlobalAdmin(claims))
	if err != nil {
		serverErr(w, "permission_validate_failed")
		return "", false
	}
	if len(unknown) > 0 {
		sendErrData(w, http.StatusBadRequest, "unknown_permission", map[string]any{"unknown_permissions": unknown})
		return "", false
	}
	if len(offending) > 0 {
		sendErrData(w, http.StatusForbidden, "permission_grant_denied", map[string]any{"offending_permissions": offending})
		return "", false
	}
	return canonical, true
}

func (s *Service) handleServiceTokensGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || claims.IsService() {
		unauthorized(w, "unauthorized")
		return
	}
	tenantSlug := strings.TrimSpace(r.PathValue("tenant"))
	if tenantSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.tenantAccessTokenManageGate(w, r, claims, tenantSlug)
	if !gateOK {
		return
	}
	tokens, err := s.svc.ListServiceTokens(r.Context(), canonical)
	if err != nil {
		serverErr(w, "access_token_list_failed")
		return
	}
	views := make([]accessTokenView, 0, len(tokens))
	for _, t := range tokens {
		views = append(views, toAccessTokenView(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"service_tokens": views})
}

func (s *Service) handleServiceTokenDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || claims.IsService() {
		unauthorized(w, "unauthorized")
		return
	}
	tenantSlug := strings.TrimSpace(r.PathValue("tenant"))
	tokenID := strings.TrimSpace(r.PathValue("token_id"))
	if tenantSlug == "" || tokenID == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.tenantAccessTokenManageGate(w, r, claims, tenantSlug)
	if !gateOK {
		return
	}
	revoked, err := s.svc.RevokeServiceToken(r.Context(), canonical, tokenID)
	if err != nil {
		serverErr(w, "access_token_revoke_failed")
		return
	}
	if !revoked {
		notFound(w, "access_token_not_found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}
