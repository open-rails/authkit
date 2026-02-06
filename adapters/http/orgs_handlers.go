package authhttp

import (
	"net/http"
	"strings"

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
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	var body struct {
		Slug string `json:"slug"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Slug) == "" {
		badRequest(w, "invalid_request")
		return
	}
	org, err := s.svc.CreateOrg(r.Context(), body.Slug)
	if err != nil {
		if err == core.ErrOwnerSlugTaken {
			badRequest(w, "owner_slug_taken")
			return
		}
		badRequest(w, "org_create_failed")
		return
	}
	// Owner bootstrap: make creator a member and assign "owner" role.
	_ = s.svc.DefineRole(r.Context(), org.Slug, "owner")
	_ = s.svc.DefineRole(r.Context(), org.Slug, "member")
	_ = s.svc.AddMember(r.Context(), org.Slug, claims.UserID)
	_ = s.svc.AssignRole(r.Context(), org.Slug, claims.UserID, "owner")

	writeJSON(w, http.StatusCreated, map[string]any{"org": org.Slug})
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
	if err := s.svc.RenameOrgSlug(r.Context(), org.ID, body.NewSlug); err != nil {
		if err == core.ErrPersonalOrgLocked {
			badRequest(w, "personal_org_locked")
			return
		}
		if err == core.ErrOwnerSlugTaken {
			badRequest(w, "owner_slug_taken")
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
