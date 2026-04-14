package authhttp

import (
	"errors"
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleAdminAccountsReservePOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	var req struct {
		Slug string `json:"slug"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Slug) == "" {
		badRequest(w, "invalid_request")
		return
	}
	userID, orgID, reserved, err := s.svc.ReserveAccount(r.Context(), req.Slug)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrInvalidOrgSlug):
			badRequest(w, "invalid_slug")
		case errors.Is(err, core.ErrOwnerSlugTaken):
			sendErr(w, http.StatusConflict, "owner_slug_taken")
		case errors.Is(err, core.ErrReservedAccountClaimed):
			sendErr(w, http.StatusConflict, "account_already_claimed")
		default:
			serverErr(w, "account_reserve_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"user_id":  strings.TrimSpace(userID),
		"org_id":   strings.TrimSpace(orgID),
		"reserved": reserved,
	})
}

func (s *Service) handleAdminAccountsStateGET(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	slug := strings.TrimSpace(r.URL.Query().Get("slug"))
	if slug == "" {
		badRequest(w, "invalid_request")
		return
	}
	state, err := s.svc.GetOwnerNamespaceStateBySlug(r.Context(), slug)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrOwnerNamespaceNotFound):
			notFound(w, "owner_namespace_not_found")
		case errors.Is(err, core.ErrInvalidOrgSlug):
			badRequest(w, "invalid_slug")
		default:
			serverErr(w, "owner_namespace_state_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"slug":  strings.ToLower(slug),
		"state": string(state),
	})
}

func (s *Service) handleAdminAccountsParkPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	var req struct {
		Slug string `json:"slug"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Slug) == "" {
		badRequest(w, "invalid_request")
		return
	}
	orgID, created, err := s.svc.PromoteReservedNameToParkedOrg(r.Context(), req.Slug)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrReservedAccountNotFound):
			notFound(w, "reserved_account_not_found")
		case errors.Is(err, core.ErrOwnerSlugTaken):
			sendErr(w, http.StatusConflict, "owner_slug_taken")
		case errors.Is(err, core.ErrInvalidOwnerNamespaceTransition):
			sendErr(w, http.StatusConflict, "invalid_owner_namespace_transition")
		case errors.Is(err, core.ErrInvalidOrgSlug):
			badRequest(w, "invalid_slug")
		default:
			serverErr(w, "account_park_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"org_id":  strings.TrimSpace(orgID),
		"created": created,
		"state":   string(core.OwnerNamespaceStateParkedOrg),
	})
}

func (s *Service) handleAdminAccountsClaimOrgPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	var req struct {
		Slug      string `json:"slug"`
		OwnerUser string `json:"owner_user_id,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Slug) == "" || strings.TrimSpace(req.OwnerUser) == "" {
		badRequest(w, "invalid_request")
		return
	}
	orgID, created, err := s.svc.ClaimOrgNamespace(r.Context(), req.Slug, req.OwnerUser)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrUserNotFound):
			notFound(w, "owner_user_not_found")
		case errors.Is(err, core.ErrOwnerMembershipRequired):
			badRequest(w, "owner_membership_required")
		case errors.Is(err, core.ErrOwnerNamespaceAlreadyClaimed):
			sendErr(w, http.StatusConflict, "org_already_claimed")
		case errors.Is(err, core.ErrOwnerSlugTaken):
			sendErr(w, http.StatusConflict, "owner_slug_taken")
		case errors.Is(err, core.ErrInvalidOwnerNamespaceTransition):
			sendErr(w, http.StatusConflict, "invalid_owner_namespace_transition")
		case errors.Is(err, core.ErrInvalidOrgSlug):
			badRequest(w, "invalid_slug")
		default:
			serverErr(w, "account_claim_org_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"org_id":  strings.TrimSpace(orgID),
		"state":   string(core.OwnerNamespaceStateRegistered),
		"created": created,
	})
}

func (s *Service) handleAdminAccountsRestrictPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	var req struct {
		Slugs []string `json:"slugs"`
	}
	if err := decodeJSON(r, &req); err != nil || len(req.Slugs) == 0 {
		badRequest(w, "invalid_request")
		return
	}

	restricted, alreadyRestricted, err := s.svc.RestrictOwnerNamespaceSlugs(r.Context(), req.Slugs)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrInvalidOrgSlug):
			badRequest(w, "invalid_slug")
		case errors.Is(err, core.ErrOwnerNamespaceBatchEmpty):
			badRequest(w, "invalid_request")
		case errors.Is(err, core.ErrOwnerSlugTaken):
			sendErr(w, http.StatusConflict, "owner_slug_taken")
		default:
			serverErr(w, "account_restrict_failed")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"restricted":         restricted,
		"already_restricted": alreadyRestricted,
	})
}

func (s *Service) handleAdminAccountsUnrestrictPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	var req struct {
		Slugs []string `json:"slugs"`
	}
	if err := decodeJSON(r, &req); err != nil || len(req.Slugs) == 0 {
		badRequest(w, "invalid_request")
		return
	}

	unrestricted, notRestricted, err := s.svc.UnrestrictOwnerNamespaceSlugs(r.Context(), req.Slugs)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrInvalidOrgSlug):
			badRequest(w, "invalid_slug")
		case errors.Is(err, core.ErrOwnerNamespaceBatchEmpty):
			badRequest(w, "invalid_request")
		default:
			serverErr(w, "account_unrestrict_failed")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"unrestricted":   unrestricted,
		"not_restricted": notRestricted,
	})
}
