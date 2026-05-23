package authhttp

import (
	"context"
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

// Organization Access Token (OAT) management endpoints. An OAT carries a set of
// app-defined PERMISSIONS (opaque to authkit). Minting authorization — whether a
// caller may grant the requested permissions — is delegated to the host via
// OATGrantAuthorizer (the app owns the permission vocabulary). Listing and
// revoking remain gated to the org owner (or a platform global admin). A service
// principal (an OAT) carries no UserID, so it can never reach these handlers: an
// OAT can never mint, list, or revoke OATs.

// OATGrantAuthorizer lets the embedding application decide whether a caller may
// mint an OAT carrying the requested permissions for an org. authkit does not
// know what app permissions mean, so it delegates this decision. The app should
// verify (a) the caller may mint OATs at all, and (b) every requested permission
// is one the caller is allowed to confer (no privilege escalation). On denial it
// returns allowed=false and the offending permission(s) for a precise error.
type OATGrantAuthorizer interface {
	CanGrantOAT(ctx context.Context, caller OATGrantCaller, org string, permissions []string) (allowed bool, offending []string, err error)
}

// OATGrantCaller identifies the human principal requesting the mint. The host
// implementation resolves the caller's authority from its own records (e.g.
// their org roles → permissions); UserID and GlobalRoles are provided so it can
// do so without trusting client-supplied claims for the decision.
type OATGrantCaller struct {
	UserID      string
	GlobalRoles []string
}

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

// orgAccessTokenManageGate resolves the org and confirms the caller may MANAGE
// the org's tokens (list/revoke): org owner, or a platform global admin. It
// writes the error response itself and returns ok=false when not permitted.
func (s *Service) orgAccessTokenManageGate(w http.ResponseWriter, r *http.Request, claims Claims, orgSlug string) (canonical string, ok bool) {
	canonical, _, isOwner, err := s.requireOrgOwner(r.Context(), claims.UserID, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return "", false
		}
		serverErr(w, "org_lookup_failed")
		return "", false
	}
	if !isOwner && !claimsHasGlobalAdmin(claims) {
		forbidden(w, "forbidden")
		return "", false
	}
	return canonical, true
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

// authorizeOATMint decides whether the caller may mint an OAT with the requested
// permissions, returning the canonical org slug. When a host OATGrantAuthorizer
// is installed, the decision is delegated to it (the app owns the permission
// vocabulary + the no-escalation rule). Otherwise authkit falls back to
// owner-only minting with no permission bounding (degraded standalone mode).
func (s *Service) authorizeOATMint(w http.ResponseWriter, r *http.Request, claims Claims, orgSlug string, permissions []string) (canonical string, ok bool) {
	if s.oatGrantAuthorizer == nil {
		// Fallback: owner (or global admin) only; permissions are not bounded
		// because authkit has no permission catalog of its own.
		return s.orgAccessTokenManageGate(w, r, claims, orgSlug)
	}
	org, err := s.svc.ResolveOrgBySlug(r.Context(), orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return "", false
		}
		serverErr(w, "org_lookup_failed")
		return "", false
	}
	caller := OATGrantCaller{UserID: claims.UserID, GlobalRoles: claims.GlobalRoles}
	allowed, offending, err := s.oatGrantAuthorizer.CanGrantOAT(r.Context(), caller, org.Slug, permissions)
	if err != nil {
		serverErr(w, "oat_grant_check_failed")
		return "", false
	}
	if !allowed {
		sendErrData(w, http.StatusForbidden, "permission_grant_denied", map[string]any{
			"offending_permissions": offending,
		})
		return "", false
	}
	return org.Slug, true
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
