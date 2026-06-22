package authhttp

import (
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

// API key management endpoints. An API key holds exactly ONE org ROLE (#95); its
// effective permissions are resolved FROM that role at use time (edit the role to
// change every key). Minting gates on org:api_keys:create, validates the role
// EXISTS in the org, enforces NO-ESCALATION (the minter must hold every permission
// the role confers), and bars a role that confers wildcards / reserved `org:`
// write-management permissions from an API key (an API key does machine work, not
// org management). A role that confers only read-only reserved perms (e.g.
// `org:*:read`) is API-key-grantable (escalation-harmless, for monitoring/audit
// automation). The bespoke-permission use case is served by a custom org role. A
// service principal (an API key) has no UserID, so it can never reach these
// handlers — an API key can never mint/list/revoke API keys.

// apiKeyView is the non-secret JSON shape returned for an API key. The secret
// is only ever present in the create response's top-level `token` field. Role is
// the single org role the key holds; Permissions is that role's resolved effective
// set (a convenience projection — edit the role to change it).
type apiKeyView struct {
	ID          string                `json:"id"`
	KeyID       string                `json:"key_id"`
	Name        string                `json:"name"`
	Role        string                `json:"role"`
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
		Role:        t.Role,
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
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	var body struct {
		Name      string                `json:"name"`
		Role      string                `json:"role"`
		Resources []core.APIKeyResource `json:"resources"`
		ExpiresAt string                `json:"expires_at"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if strings.TrimSpace(body.Name) == "" {
		badRequest(w, ErrMissingName)
		return
	}
	role := strings.TrimSpace(body.Role)
	if role == "" {
		badRequest(w, ErrMissingRole)
		return
	}

	var expiresAt *time.Time
	if ts := strings.TrimSpace(body.ExpiresAt); ts != "" {
		parsed, err := time.Parse(time.RFC3339, ts)
		if err != nil || !parsed.After(time.Now().UTC()) {
			badRequest(w, ErrInvalidExpiry)
			return
		}
		expiresAt = &parsed
	}

	resources := body.Resources

	// Authorize the mint + the role grant. Returns the role's resolved effective
	// permissions (for the resource-scope no-escalation hook).
	canonical, rolePerms, ok := s.authorizeAPIKeyMint(w, r, claims, orgSlug, role)
	if !ok {
		return
	}
	if err := s.svc.AuthorizeAPIKeyResources(r.Context(), core.ResourceScopeAuthorizationRequest{
		OrgSlug:     canonical,
		ActorUserID: claims.UserID,
		Permissions: rolePerms,
		Resources:   resources,
	}); err != nil {
		switch err.Error() {
		case "invalid_resource":
			badRequest(w, ErrInvalidResource)
		case "duplicate_resource":
			badRequest(w, ErrDuplicateResource)
		default:
			sendErrData(w, http.StatusForbidden, ErrResourceScopeDenied, map[string]any{})
		}
		return
	}

	tok, plaintext, err := s.svc.MintAPIKeyWithOptions(r.Context(), canonical, core.APIKeyMintOptions{
		Name:      body.Name,
		Role:      role,
		Resources: resources,
		CreatedBy: claims.UserID,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		switch err.Error() {
		case "invalid_expiry":
			badRequest(w, ErrInvalidExpiry)
		case "missing_name":
			badRequest(w, ErrMissingName)
		case "invalid_role":
			badRequest(w, ErrInvalidRole)
		case "unknown_role":
			sendErrData(w, http.StatusBadRequest, ErrUnknownRole, map[string]any{"role": role})
		case "invalid_resource":
			badRequest(w, ErrInvalidResource)
		case "duplicate_resource":
			badRequest(w, ErrDuplicateResource)
		default:
			serverErr(w, ErrAccessTokenCreateFailed)
		}
		return
	}

	view := toAPIKeyView(tok)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":     view.ID,
		"key_id": view.KeyID,
		"name":   view.Name,
		"role":   view.Role,
		// The role's resolved effective permissions, surfaced for convenience.
		"permissions": view.Permissions,
		"resources":   view.Resources,
		"created_at":  view.CreatedAt,
		"expires_at":  view.ExpiresAt,
		// Shown ONCE — never retrievable again.
		"token": plaintext,
	})
}

// authorizeAPIKeyMint gates minting on org:api_keys:create and validates the
// requested ROLE (#95). The role must EXIST in the org. NO-ESCALATION: the minter
// must hold every permission the role confers (the role's RAW grant tokens are
// validated against the minter's effective set via ValidateGrant). The role must
// also not confer anything an API key may not hold — a bare `*` or a reserved
// `org:` WRITE-management permission (an API key does machine work, not org
// management; read globs like `org:*:read` are fine). Returns the role's resolved
// effective permission set for the resource-scope hook. Negation was removed in
// #93 — positive grants only.
func (s *Service) authorizeAPIKeyMint(w http.ResponseWriter, r *http.Request, claims Claims, orgSlug, role string) (canonical string, rolePerms []string, ok bool) {
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgAPIKeysCreate)
	if !gateOK {
		return "", nil, false
	}
	// The role must exist; surface its RAW grant tokens (literals + globs) so
	// no-escalation expands them exactly like a role assignment.
	roleTokens, err := s.svc.GetRolePermissions(r.Context(), canonical, role)
	if err != nil {
		serverErr(w, ErrPermissionValidateFailed)
		return "", nil, false
	}
	exists, err := s.svc.OrgRoleExists(r.Context(), canonical, role)
	if err != nil {
		serverErr(w, ErrPermissionValidateFailed)
		return "", nil, false
	}
	if !exists {
		sendErrData(w, http.StatusBadRequest, ErrUnknownRole, map[string]any{"role": role})
		return "", nil, false
	}
	// Resolve the role to its CONCRETE effective permission set; an API key may
	// not hold a wildcard or a reserved write-management perm.
	rolePerms, err = s.svc.EffectiveRolePermissions(r.Context(), canonical, role)
	if err != nil {
		serverErr(w, ErrPermissionValidateFailed)
		return "", nil, false
	}
	var notGrantable []string
	for _, p := range rolePerms {
		if p == core.PermWildcard || (core.IsReservedPermission(p) && !core.IsAPIKeyGrantableReservedPermission(p)) {
			notGrantable = append(notGrantable, p)
		}
	}
	if len(notGrantable) > 0 {
		sendErrData(w, http.StatusForbidden, ErrRoleNotGrantableToAPIKey, map[string]any{"role": role, "offending_permissions": notGrantable})
		return "", nil, false
	}
	// No-escalation: the minter must hold everything the role's tokens confer.
	unknown, offending, err := s.svc.ValidateGrant(r.Context(), canonical, claims.UserID, roleTokens, false)
	if err != nil {
		serverErr(w, ErrPermissionValidateFailed)
		return "", nil, false
	}
	if len(unknown) > 0 {
		sendErrData(w, http.StatusBadRequest, ErrUnknownPermission, map[string]any{"unknown_permissions": unknown})
		return "", nil, false
	}
	if len(offending) > 0 {
		sendErrData(w, http.StatusForbidden, ErrPermissionGrantDenied, map[string]any{"offending_permissions": offending})
		return "", nil, false
	}
	return canonical, rolePerms, true
}

func (s *Service) handleAPIKeysGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || claims.IsService() {
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, gateOK := s.orgAPIKeyGate(w, r, claims, orgSlug, core.PermOrgAPIKeysRead)
	if !gateOK {
		return
	}
	tokens, err := s.svc.ListAPIKeys(r.Context(), canonical)
	if err != nil {
		serverErr(w, ErrAccessTokenListFailed)
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
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	tokenID := strings.TrimSpace(r.PathValue("token_id"))
	if orgSlug == "" || tokenID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, gateOK := s.orgAPIKeyGate(w, r, claims, orgSlug, core.PermOrgAPIKeysDelete)
	if !gateOK {
		return
	}
	revoked, err := s.svc.RevokeAPIKey(r.Context(), canonical, tokenID)
	if err != nil {
		serverErr(w, ErrAccessTokenRevokeFailed)
		return
	}
	if !revoked {
		notFound(w, ErrAccessTokenNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}
