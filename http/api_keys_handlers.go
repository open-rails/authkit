package authhttp

import (
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

// API key management endpoints. An API key carries a set of
// app-defined PERMISSIONS (opaque to authkit). All three endpoints are gated by
// the base permission org:api_keys:manage (owner holds `*`; a platform global
// admin bypasses). Minting validates the requested permissions against the
// catalog AND the caller's own effective permissions (no-escalation), and bars
// wildcards + the write/mint reserved `org:` management permissions from API
// keys (an API key does machine work, not org management). Read-only org:read IS
// API-key-grantable (escalation-harmless, for monitoring/audit automation). A
// service principal (an API key) has no UserID, so it can never reach these
// handlers — an API key can never mint/list/revoke API keys.

// apiKeyView is the non-secret JSON shape returned for an API key. The secret
// is only ever present in the create response's top-level `token` field.
type apiKeyView struct {
	ID          string                `json:"id"`
	KeyID       string                `json:"key_id"`
	Name        string                `json:"name"`
	Permissions []string              `json:"permissions"`
	Resources   []core.APIKeyResource `json:"resources"`
	CreatedBy   string                `json:"created_by,omitempty"`
	CreatedAt   string                `json:"created_at"`
	LastUsedAt  string                `json:"last_used_at,omitempty"`
	ExpiresAt   string                `json:"expires_at,omitempty"`
	RevokedAt   string                `json:"revoked_at,omitempty"`
}

func rfc3339Ptr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func toAPIKeyView(t core.APIKey) apiKeyView {
	perms := t.Permissions
	if perms == nil {
		perms = []string{}
	}
	resources := t.Resources
	if resources == nil {
		resources = []core.APIKeyResource{}
	}
	return apiKeyView{
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

func (s *Service) orgAPIKeyGate(w http.ResponseWriter, r *http.Request, claims Claims, orgSlug, perm string) (canonical string, ok bool) {
	return s.requireOrgPermissionGin(w, r, claims, orgSlug, perm)
}

func (s *Service) handleAPIKeysPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	// An API-key principal has no UserID; this both authenticates a human admin
	// and structurally prevents an API key from minting another API key.
	if !ok || strings.TrimSpace(claims.UserID) == "" || claims.IsService() {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, "invalid_request")
		return
	}

	var body struct {
		Name        string                `json:"name"`
		Permissions []string              `json:"permissions"`
		Resources   []core.APIKeyResource `json:"resources"`
		ExpiresAt   string                `json:"expires_at"`
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
	canonical, ok := s.authorizeAPIKeyMint(w, r, claims, orgSlug, permissions)
	if !ok {
		return
	}
	if err := s.svc.AuthorizeAPIKeyResources(r.Context(), core.ResourceScopeAuthorizationRequest{
		OrgSlug:          canonical,
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

	tok, plaintext, err := s.svc.MintAPIKeyWithOptions(r.Context(), canonical, core.APIKeyMintOptions{
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

	view := toAPIKeyView(tok)
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

// authorizeAPIKeyMint gates minting on org:api_keys:create and validates the
// requested permissions: they must be permissions the caller itself holds
// (no-escalation) — never a bare `*` or reserved `org:` write permissions (an
// API key does machine work, not org management; read globs like `org:*:read`
// are allowed). Negation was removed in #93 — positive grants only.
func (s *Service) authorizeAPIKeyMint(w http.ResponseWriter, r *http.Request, claims Claims, orgSlug string, permissions []string) (canonical string, ok bool) {
	var notGrantable []string
	for _, p := range permissions {
		if p == core.PermWildcard || (core.IsReservedPermission(p) && !core.IsAPIKeyGrantableReservedPermission(p)) {
			notGrantable = append(notGrantable, p)
		}
	}
	if len(notGrantable) > 0 {
		sendErrData(w, http.StatusForbidden, "permission_not_grantable_to_api_key", map[string]any{"offending_permissions": notGrantable})
		return "", false
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgAPIKeysCreate)
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

func (s *Service) handleAPIKeysGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || claims.IsService() {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.orgAPIKeyGate(w, r, claims, orgSlug, core.PermOrgAPIKeysRead)
	if !gateOK {
		return
	}
	tokens, err := s.svc.ListAPIKeys(r.Context(), canonical)
	if err != nil {
		serverErr(w, "access_token_list_failed")
		return
	}
	views := make([]apiKeyView, 0, len(tokens))
	for _, t := range tokens {
		views = append(views, toAPIKeyView(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"api_keys": views,
	})
}

func (s *Service) handleAPIKeyDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || claims.IsService() {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	tokenID := strings.TrimSpace(r.PathValue("token_id"))
	if orgSlug == "" || tokenID == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.orgAPIKeyGate(w, r, claims, orgSlug, core.PermOrgAPIKeysDelete)
	if !gateOK {
		return
	}
	revoked, err := s.svc.RevokeAPIKey(r.Context(), canonical, tokenID)
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
