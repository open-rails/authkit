package authhttp

import (
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

// Organization Access Token (OAT) management endpoints. An OAT carries a set of
// app-defined PERMISSIONS (opaque to authkit). All three endpoints are gated by
// the base permission org:tokens:manage (owner holds `*`; a platform global
// admin bypasses). Minting validates the requested permissions against the
// catalog AND the caller's own effective permissions (no-escalation), and bars
// wildcards + the write/mint reserved `org:` management permissions from OATs
// (an OAT does machine work, not org management). Read-only org:read IS
// OAT-grantable (escalation-harmless, for monitoring/audit automation). A
// service principal (an OAT) has no UserID,
// so it can never reach these handlers — an OAT can never mint/list/revoke OATs.

// accessTokenView is the non-secret JSON shape returned for an OAT. The secret
// is only ever present in the create response's top-level `token` field.
type accessTokenView struct {
	ID          string   `json:"id"`
	KeyID       string   `json:"key_id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	CreatedBy   string   `json:"created_by,omitempty"`
	CreatedAt   string   `json:"created_at"`
	LastUsedAt  string   `json:"last_used_at,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	RevokedAt   string   `json:"revoked_at,omitempty"`
}

func rfc3339Ptr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func toAccessTokenView(t core.OrgAccessToken) accessTokenView {
	perms := t.Permissions
	if perms == nil {
		perms = []string{}
	}
	return accessTokenView{
		ID:          t.ID,
		KeyID:       t.KeyID,
		Name:        t.Name,
		Permissions: perms,
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

// orgAccessTokenManageGate resolves the org and confirms the caller holds
// org:tokens:manage (list/revoke). Owner holds `*`; a global admin bypasses.
func (s *Service) orgAccessTokenManageGate(w http.ResponseWriter, r *http.Request, claims Claims, orgSlug string) (canonical string, ok bool) {
	return s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgTokensManage)
}

func (s *Service) handleOrgAccessTokensPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	// A service principal (OAT) has no UserID; this both authenticates a human
	// admin and structurally prevents an OAT from minting another OAT.
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
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
		ExpiresAt   string   `json:"expires_at"`
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

	// Authorize the mint + the permission grant.
	canonical, ok := s.authorizeOATMint(w, r, claims, orgSlug, permissions)
	if !ok {
		return
	}

	tok, plaintext, err := s.svc.MintOrgAccessToken(r.Context(), canonical, body.Name, permissions, claims.UserID, expiresAt)
	if err != nil {
		switch err.Error() {
		case "invalid_expiry":
			badRequest(w, "invalid_expiry")
		case "missing_name":
			badRequest(w, "missing_name")
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
		"created_at":  view.CreatedAt,
		"expires_at":  view.ExpiresAt,
		// Shown ONCE — never retrievable again.
		"token": plaintext,
	})
}

// authorizeOATMint gates minting on org:tokens:manage and validates the
// requested permissions: they must be concrete catalog permissions the caller
// itself holds (no-escalation) — never wildcards/exclusions or reserved `org:`
// management permissions (an OAT does machine work, not org management).
func (s *Service) authorizeOATMint(w http.ResponseWriter, r *http.Request, claims Claims, orgSlug string, permissions []string) (canonical string, ok bool) {
	var notGrantable []string
	for _, p := range permissions {
		if p == core.PermWildcard || strings.HasPrefix(p, "!") || (core.IsReservedPermission(p) && !core.IsOATGrantableReservedPermission(p)) {
			notGrantable = append(notGrantable, p)
		}
	}
	if len(notGrantable) > 0 {
		sendErrData(w, http.StatusForbidden, "permission_not_grantable_to_oat", map[string]any{"offending_permissions": notGrantable})
		return "", false
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgTokensManage)
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

func (s *Service) handleOrgAccessTokensGET(w http.ResponseWriter, r *http.Request) {
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
	canonical, gateOK := s.orgAccessTokenManageGate(w, r, claims, orgSlug)
	if !gateOK {
		return
	}
	tokens, err := s.svc.ListOrgAccessTokens(r.Context(), canonical)
	if err != nil {
		serverErr(w, "access_token_list_failed")
		return
	}
	views := make([]accessTokenView, 0, len(tokens))
	for _, t := range tokens {
		views = append(views, toAccessTokenView(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_tokens": views})
}

func (s *Service) handleOrgAccessTokenDELETE(w http.ResponseWriter, r *http.Request) {
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
	canonical, gateOK := s.orgAccessTokenManageGate(w, r, claims, orgSlug)
	if !gateOK {
		return
	}
	revoked, err := s.svc.RevokeOrgAccessToken(r.Context(), canonical, tokenID)
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
