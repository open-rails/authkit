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
		unauthorized(w, ErrUnauthorized)
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
		serverErr(w, ErrOrgsListFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"orgs": orgs})
}

// handleAdminOrgsDeletedListGET lists soft-deleted orgs (the directory's
// deleted view). Gate: platform:orgs:read. Reuses AdminListOrgs with
// include_deleted; the soft-deleted rows carry a non-nil deleted_at.
func (s *Service) handleAdminOrgsDeletedListGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, ErrUnauthorized)
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformOrgsRead) {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(strings.TrimSpace(q.Get("limit")))
	offset, _ := strconv.Atoi(strings.TrimSpace(q.Get("offset")))
	all, err := s.svc.AdminListOrgs(r.Context(), q.Get("search"), true, int32(limit), int32(offset))
	if err != nil {
		serverErr(w, ErrOrgsListFailed)
		return
	}
	orgs := make([]core.OrgAdminSummary, 0, len(all))
	for _, o := range all {
		if o.DeletedAt != nil {
			orgs = append(orgs, o)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"orgs": orgs})
}

func (s *Service) handleAdminOrgGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, ErrUnauthorized)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformOrgsRead) {
		return
	}
	detail, err := s.svc.AdminOrgDetail(r.Context(), id)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, ErrOrgNotFound)
			return
		}
		serverErr(w, ErrOrgDetailFailed)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// handleAdminOrgRenamePOST renames any org as a platform admin (the admin-side
// equivalent of /orgs/{org}/rename). Gate: platform:orgs:update. Uses the
// admin-override rename path (RenameOrgSlugForce) so the 72h self-service
// cooldown does not apply to operator action.
func (s *Service) handleAdminOrgRenamePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, ErrUnauthorized)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformOrgsUpdate) {
		return
	}
	var body struct {
		NewSlug string `json:"new_slug"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.NewSlug) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.RenameOrgSlugForce(r.Context(), id, body.NewSlug, claims.UserID); err != nil {
		switch err {
		case core.ErrOrgNotFound:
			notFound(w, ErrOrgNotFound)
		case core.ErrPersonalOrgLocked:
			badRequest(w, ErrPersonalOrgLocked)
		case core.ErrOwnerSlugTaken:
			badRequest(w, ErrOwnerSlugTaken)
		case core.ErrInvalidOrgSlug:
			badRequest(w, ErrInvalidSlug)
		default:
			serverErr(w, ErrOrgRenameFailed)
		}
		return
	}
	renamed, err := s.svc.ResolveOrgByID(r.Context(), id)
	if err != nil {
		serverErr(w, ErrOrgLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"org": renamed.Slug})
}

// handleAdminOrgTransferOwnerPOST surgically reassigns an org's owner (the
// owner-left / white-glove path that keeps the team). Body: {new_owner_user_id}.
// Gate: platform:orgs:update. Demotes the prior owner(s) and assigns `owner`
// (org:*) to the new owner; all other members keep their roles.
func (s *Service) handleAdminOrgTransferOwnerPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, ErrUnauthorized)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformOrgsUpdate) {
		return
	}
	var body struct {
		NewOwnerUserID string `json:"new_owner_user_id"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.NewOwnerUserID) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	res, err := s.svc.TransferOrgOwner(r.Context(), id, body.NewOwnerUserID)
	if err != nil {
		switch err {
		case core.ErrRecoverInvalid:
			badRequest(w, ErrInvalidRequest)
		case core.ErrOrgNotFound:
			notFound(w, ErrOrgNotFound)
		case core.ErrUserNotFound:
			notFound(w, ErrUserNotFound)
		default:
			serverErr(w, ErrOrgTransferOwnerFailed)
		}
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Service) handleAdminOrgDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, ErrUnauthorized)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformOrgsDelete) {
		return
	}
	removed, err := s.svc.SoftDeleteOrg(r.Context(), id)
	if err != nil {
		serverErr(w, ErrOrgSoftDeleteFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": removed})
}

func (s *Service) handleAdminOrgRestorePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, ErrUnauthorized)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformOrgsDelete) {
		return
	}
	restored, err := s.svc.RestoreOrg(r.Context(), id)
	if err != nil {
		serverErr(w, ErrOrgRestoreFailed)
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
		unauthorized(w, ErrUnauthorized)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if !s.requirePlatformPermission(w, r, claims, core.PermPlatformOrgsRecover) {
		return
	}
	if !s.requireFreshAuthOrPassword(w, r, claims, "") {
		return
	}
	var body struct {
		NewOwnerUserID string `json:"new_owner_user_id"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.NewOwnerUserID) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	res, err := s.svc.RecoverOrg(r.Context(), id, body.NewOwnerUserID)
	if err != nil {
		if err == core.ErrRecoverInvalid {
			badRequest(w, ErrInvalidRequest)
			return
		}
		if err == core.ErrUserNotFound {
			notFound(w, ErrUserNotFound)
			return
		}
		serverErr(w, ErrOrgRecoverFailed)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
