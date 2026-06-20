package authhttp

import (
	"net/http"
	"strconv"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// Org-admin HTTP layer (#95, Layer-2 `platform:orgs:*`). The platform-admin
// surface for administering ANY org as an ENTITY — the directory, soft-delete /
// restore, and the anti-takeover `recover` reset. Entity-level ONLY: there are
// NO endpoints here for an org's day-to-day internals (members/roles/api-keys);
// `recover` is the single coarse, all-or-nothing exception. Each handler gates
// in-handler on the specific `platform:orgs:*` permission. Orgs are addressed by
// ID (the list returns ids), which is unambiguous across soft-deleted/reused slugs.

func (s *Service) handleAdminOrgsListGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformOrgsRead) {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(strings.TrimSpace(q.Get("limit")))
	offset, _ := strconv.Atoi(strings.TrimSpace(q.Get("offset")))
	orgs, err := s.svc.AdminListOrgs(r.Context(), q.Get("search"), q.Get("include_deleted") == "true", int32(limit), int32(offset))
	if err != nil {
		serverErr(w, "orgs_list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"orgs": orgs})
}

func (s *Service) handleAdminOrgGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformOrgsRead) {
		return
	}
	detail, err := s.svc.AdminOrgDetail(r.Context(), id)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_detail_failed")
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Service) handleAdminOrgDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformOrgsDelete) {
		return
	}
	removed, err := s.svc.SoftDeleteOrg(r.Context(), id)
	if err != nil {
		serverErr(w, "org_soft_delete_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": removed})
}

func (s *Service) handleAdminOrgRestorePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformOrgsDelete) {
		return
	}
	restored, err := s.svc.RestoreOrg(r.Context(), id)
	if err != nil {
		serverErr(w, "org_restore_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": restored})
}

// handleAdminOrgRecoverPOST runs the anti-takeover reset on a compromised org:
// revoke ALL api-keys, disable ALL remote-apps, demote ALL members, and restore
// the rightful owner. Gate: platform:orgs:recover (the single sanctioned coarse
// reach inside an org; separately grantable, max-audited).
func (s *Service) handleAdminOrgRecoverPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformOrgsRecover) {
		return
	}
	var body struct {
		NewOwnerUserID string `json:"new_owner_user_id"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.NewOwnerUserID) == "" {
		badRequest(w, "invalid_request")
		return
	}
	res, err := s.svc.RecoverOrg(r.Context(), id, body.NewOwnerUserID)
	if err != nil {
		if err == core.ErrRecoverInvalid {
			badRequest(w, "invalid_request")
			return
		}
		if err == core.ErrUserNotFound {
			notFound(w, "user_not_found")
			return
		}
		serverErr(w, "org_recover_failed")
		return
	}
	writeJSON(w, http.StatusOK, res)
}
