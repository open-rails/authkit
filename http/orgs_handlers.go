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
		unauthorized(w, "unauthorized")
		return
	}
	mems, err := s.svc.ListUserOrgMembershipsAndRoles(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "orgs_lookup_failed")
		return
	}
	type orgItem struct {
		Org   string   `json:"org"`
		Roles []string `json:"roles"`
	}
	out := make([]orgItem, 0, len(mems))
	for _, m := range mems {
		out = append(out, orgItem{Org: m.Org, Roles: m.Roles})
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
		unauthorized(w, "unauthorized")
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
		badRequest(w, "invalid_request")
		return
	}
	// Validate the federation block BEFORE creating anything, so an invalid
	// block rejects the whole registration (no org created).
	if body.Federation != nil {
		if strings.TrimSpace(body.Federation.Issuer) == "" {
			badRequest(w, "invalid_federation_issuer")
			return
		}
		if _, err := core.NormalizeRemoteAppTrustSource(body.Federation.JWKSURI, body.Federation.Mode, body.Federation.PublicKeys); err != nil {
			badRequest(w, "invalid_federation_trust_source")
			return
		}
	}
	org, err := s.svc.CreateOrgForUser(r.Context(), core.CreateOrgForUserRequest{
		Slug:        body.Slug,
		OwnerUserID: claims.UserID,
	})
	if err != nil {
		if err == core.ErrInvalidOrgSlug {
			badRequest(w, "invalid_org_slug")
			return
		}
		if err == core.ErrOwnerSlugTaken {
			badRequest(w, "owner_slug_taken")
			return
		}
		if err == core.ErrInvalidOrgOwner {
			forbidden(w, "invalid_org_owner")
			return
		}
		if err == core.ErrOrgLimitExceeded {
			forbidden(w, "org_limit_exceeded")
			return
		}
		badRequest(w, "org_create_failed")
		return
	}

	resp := map[string]any{"org": org.Slug}
	if body.Federation != nil {
		raSlug := strings.TrimSpace(body.Federation.Slug)
		if raSlug == "" {
			raSlug = org.Slug
		}
		ra, err := s.svc.UpsertRemoteApplication(r.Context(), core.RemoteApplication{
			Slug:        raSlug,
			OwnerUserID: claims.UserID,
			Issuer:      body.Federation.Issuer,
			JWKSURI:     body.Federation.JWKSURI,
			Mode:        body.Federation.Mode,
			PublicKeys:  body.Federation.PublicKeys,
			Audiences:   body.Federation.Audiences,
			Enabled:     true,
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
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, member, err := s.requireOrgMember(r.Context(), claims.UserID, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_lookup_failed")
		return
	}
	if !member {
		forbidden(w, "not_org_member")
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
	writeJSON(w, http.StatusOK, map[string]any{"org": canonical})
}

func (s *Service) handleOrgsRenamePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, _, isOwner, err := s.requireOrgOwner(r.Context(), claims.UserID, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_lookup_failed")
		return
	}
	if !isOwner {
		forbidden(w, "forbidden")
		return
	}
	var body struct {
		NewSlug string `json:"new_slug"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.NewSlug) == "" {
		badRequest(w, "invalid_request")
		return
	}
	org, err := s.svc.ResolveOrgBySlug(r.Context(), canonical)
	if err != nil {
		serverErr(w, "org_lookup_failed")
		return
	}
	if err := s.svc.RenameOrgSlug(r.Context(), org.ID, body.NewSlug, claims.UserID); err != nil {
		if err == core.ErrPersonalOrgLocked {
			badRequest(w, "personal_org_locked")
			return
		}
		if err == core.ErrOwnerSlugTaken {
			badRequest(w, "owner_slug_taken")
			return
		}
		if err == core.ErrRenameRateLimited {
			seconds, _ := s.svc.TimeUntilOrgRenameAvailable(r.Context(), org.ID, time.Now())
			availability := cooldownAvailability("rename_org", seconds, 72*time.Hour, time.Now())
			data := availability.toMap()
			data["error"] = core.ErrCodeRenameRateLimited
			writeJSON(w, http.StatusTooManyRequests, data)
			return
		}
		badRequest(w, "org_rename_failed")
		return
	}
	// Return canonical slug after rename.
	renamed, err := s.svc.ResolveOrgBySlug(r.Context(), body.NewSlug)
	if err != nil {
		serverErr(w, "org_lookup_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"org": renamed.Slug})
}
