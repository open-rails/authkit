package authhttp

import (
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleOrgsListGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	mems, err := s.svc.ListUserOrgMembershipsAndRoles(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrOrgsLookupFailed)
		return
	}
	type orgItem struct {
		Org  string `json:"org"`
		Role string `json:"role"`
	}
	out := make([]orgItem, 0, len(mems))
	for _, m := range mems {
		out = append(out, orgItem{Org: m.Org, Role: firstRole(m.Roles)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"orgs": out})
}

func (s *Service) handleOrgsCreatePOST(w http.ResponseWriter, r *http.Request) {
	if s.publicOrgManagementDisabled() {
		orgManagementDisabled(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	var body struct {
		Slug string `json:"slug"`
		// Federation optionally registers a remote_application (federation
		// principal, #74) and binds it as a member of the org at creation: the
		// human plants the trust anchor exactly once. The block is {issuer +
		// jwks_uri} XOR {issuer + public_keys} — one trust source, never both.
		// Slug defaults to the org slug. Trust-config changes after creation
		// stay human-only via the remote-application routes.
		Federation *remoteApplicationRegistration `json:"federation,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Slug) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	// Validate the federation block BEFORE creating anything, so an invalid
	// block rejects the whole registration (no org created).
	if body.Federation != nil {
		if strings.TrimSpace(body.Federation.Issuer) == "" {
			badRequest(w, ErrInvalidFederationIssuer)
			return
		}
		if _, err := core.NormalizeRemoteAppTrustSource(body.Federation.JWKSURI, body.Federation.Mode, body.Federation.PublicKeys); err != nil {
			badRequest(w, ErrInvalidFederationTrustSource)
			return
		}
	}
	org, err := s.svc.CreateOrgForUser(r.Context(), core.CreateOrgForUserRequest{
		Slug:        body.Slug,
		OwnerUserID: claims.UserID,
	})
	if err != nil {
		if err == core.ErrInvalidOrgSlug {
			badRequest(w, ErrInvalidOrgSlug)
			return
		}
		if err == core.ErrOwnerSlugTaken {
			badRequest(w, ErrOwnerSlugTaken)
			return
		}
		if err == core.ErrInvalidOrgOwner {
			forbidden(w, ErrInvalidOrgOwner)
			return
		}
		if err == core.ErrOrgLimitExceeded {
			forbidden(w, ErrOrgLimitExceeded)
			return
		}
		badRequest(w, ErrOrgCreateFailed)
		return
	}

	resp := map[string]any{"org": org.Slug}
	if body.Federation != nil {
		raSlug := strings.TrimSpace(body.Federation.Slug)
		if raSlug == "" {
			raSlug = org.Slug
		}
		ra, err := s.svc.UpsertRemoteApplication(r.Context(), core.RemoteApplication{
			Slug:       raSlug,
			OrgID:      org.ID, // #77: each issuer belongs to exactly one org
			Issuer:     body.Federation.Issuer,
			JWKSURI:    body.Federation.JWKSURI,
			Mode:       body.Federation.Mode,
			PublicKeys: body.Federation.PublicKeys,
			Audiences:  body.Federation.Audiences,
			Enabled:    true,
		})
		if err == nil {
			err = s.svc.AddRemoteApplicationMember(r.Context(), org.Slug, ra.ID, "member")
		}
		if err != nil {
			// The block was pre-validated, so this is unexpected; the org
			// exists but is unfederated. Surface that honestly — the caller can
			// bind via the remote-application routes (same human credential).
			s.logInternalError(r, "orgs_create", "federation_bind", "org_created_federation_failed", err)
			writeJSON(w, http.StatusCreated, map[string]any{
				"org":              org.Slug,
				"federation_error": "org_created_federation_failed",
			})
			return
		}
		if s.verifier != nil {
			_ = s.verifier.AddIssuer(ra.Issuer, nil, remoteAppOptions(*ra))
		}
		resp["federation"] = remoteApplicationView(*ra)
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Service) handleOrgsGetGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, member, err := s.requireOrgMember(r.Context(), claims.UserID, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, ErrOrgNotFound)
			return
		}
		serverErr(w, ErrOrgLookupFailed)
		return
	}
	if !member {
		forbidden(w, ErrNotOrgMember)
		return
	}
	// Issue #58: emit a 301 redirect when the request used a historical
	// slug. requireOrgMember already resolved through `org_renames`
	// (which ResolveOrgBySlug consults on alias miss), so `canonical`
	// here is the live `orgs.slug`. If the inbound differs, the caller
	// dropped in a renamed-away name and gets pointed at the new path.
	if !strings.EqualFold(orgSlug, canonical) {
		newPath := strings.Replace(r.URL.Path, orgSlug, canonical, 1)
		if r.URL.RawQuery != "" {
			newPath += "?" + r.URL.RawQuery
		}
		w.Header().Set("Location", newPath)
		w.WriteHeader(http.StatusMovedPermanently)
		return
	}
	org, err := s.svc.ResolveOrgBySlug(r.Context(), canonical)
	if err != nil {
		serverErr(w, ErrOrgLookupFailed)
		return
	}
	roles, err := s.svc.ReadMemberRoles(r.Context(), canonical, claims.UserID)
	if err != nil {
		serverErr(w, ErrOrgMembershipLookupFailed)
		return
	}
	perms, err := s.svc.EffectivePermissions(r.Context(), canonical, claims.UserID)
	if err != nil {
		serverErr(w, ErrPermissionsLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"org": map[string]any{
			"id":            org.ID,
			"slug":          org.Slug,
			"is_personal":   org.IsPersonal,
			"owner_user_id": org.OwnerUserID,
		},
		"membership": map[string]any{
			"role":        firstRole(roles),
			"permissions": nonNil(perms),
		},
	})
}

func firstRole(roles []string) string {
	for _, role := range roles {
		if role = strings.TrimSpace(role); role != "" {
			return role
		}
	}
	return ""
}

func (s *Service) handleOrgsRenamePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, _, isOwner, err := s.requireOrgOwner(r.Context(), claims.UserID, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, ErrOrgNotFound)
			return
		}
		serverErr(w, ErrOrgLookupFailed)
		return
	}
	if !isOwner {
		forbidden(w, ErrForbidden)
		return
	}
	var body struct {
		NewSlug string `json:"new_slug"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.NewSlug) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	org, err := s.svc.ResolveOrgBySlug(r.Context(), canonical)
	if err != nil {
		serverErr(w, ErrOrgLookupFailed)
		return
	}
	if err := s.svc.RenameOrgSlug(r.Context(), org.ID, body.NewSlug, claims.UserID); err != nil {
		if err == core.ErrPersonalOrgLocked {
			badRequest(w, ErrPersonalOrgLocked)
			return
		}
		if err == core.ErrOwnerSlugTaken {
			badRequest(w, ErrOwnerSlugTaken)
			return
		}
		if err == core.ErrRenameRateLimited {
			seconds, _ := s.svc.TimeUntilOrgRenameAvailable(r.Context(), org.ID, time.Now())
			availability := cooldownAvailability("rename_org", seconds, 72*time.Hour, time.Now())
			data := availability.toMap()
			data["error"] = ErrRenameRateLimited
			writeJSON(w, http.StatusTooManyRequests, data)
			return
		}
		badRequest(w, ErrOrgRenameFailed)
		return
	}
	// Return canonical slug after rename.
	renamed, err := s.svc.ResolveOrgBySlug(r.Context(), body.NewSlug)
	if err != nil {
		serverErr(w, ErrOrgLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"org": renamed.Slug})
}
