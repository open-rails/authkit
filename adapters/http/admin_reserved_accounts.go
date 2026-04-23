package authhttp

import (
	"errors"
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

const ownerNamespaceStateRegisteredUser = "registered_user"
const ownerNamespaceStateParkedUser = "parked_user"

const (
	adminAccountKindOrg  = "org"
	adminAccountKindUser = "user"
)

type ownerNamespaceOrgPublicInfo struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	IsPersonal  bool   `json:"is_personal"`
	OwnerUserID string `json:"owner_user_id,omitempty"`
	State       string `json:"state"`
}

type ownerNamespaceUserPublicInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type ownerNamespaceLookupResponse struct {
	OK         bool                          `json:"ok"`
	Slug       string                        `json:"slug"`
	State      string                        `json:"state"`
	Exists     bool                          `json:"exists"`
	EntityKind string                        `json:"entity_kind"`
	Org        *ownerNamespaceOrgPublicInfo  `json:"org,omitempty"`
	User       *ownerNamespaceUserPublicInfo `json:"user,omitempty"`
}

func (s *Service) handleOwnerNamespaceInfoGET(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(r.PathValue("slug"))
	if slug == "" {
		badRequest(w, "invalid_request")
		return
	}

	resp := ownerNamespaceLookupResponse{
		OK:    true,
		Slug:  strings.ToLower(slug),
		State: "unregistered",
	}

	state, err := s.svc.GetOwnerNamespaceStateBySlug(r.Context(), slug)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrOwnerNamespaceNotFound):
			// Keep default unregistered state.
		case errors.Is(err, core.ErrInvalidOrgSlug):
			badRequest(w, "invalid_slug")
			return
		default:
			serverErr(w, "owner_namespace_info_failed")
			return
		}
	} else {
		resp.State = string(state)
		if state == core.OwnerNamespaceStateParkedOrg || state == core.OwnerNamespaceStateRegistered {
			org, resolveErr := s.svc.ResolveOrgBySlug(r.Context(), slug)
			if resolveErr != nil {
				serverErr(w, "owner_namespace_info_failed")
				return
			}
			orgState, orgStateErr := s.svc.GetOrgNamespaceState(r.Context(), org.ID)
			if orgStateErr != nil {
				serverErr(w, "owner_namespace_info_failed")
				return
			}
			resp.Org = &ownerNamespaceOrgPublicInfo{
				ID:          strings.TrimSpace(org.ID),
				Slug:        strings.TrimSpace(org.Slug),
				IsPersonal:  org.IsPersonal,
				OwnerUserID: strings.TrimSpace(org.OwnerUserID),
				State:       string(orgState),
			}
			resp.State = string(orgState)
		}
	}

	if state != core.OwnerNamespaceStateRestrictedName || errors.Is(err, core.ErrOwnerNamespaceNotFound) {
		userID, username, resolveErr := s.svc.ResolveUserBySlug(r.Context(), slug)
		switch {
		case resolveErr == nil:
			resp.User = &ownerNamespaceUserPublicInfo{
				ID:       strings.TrimSpace(userID),
				Username: strings.TrimSpace(username),
			}
		case errors.Is(resolveErr, core.ErrUserNotFound):
		default:
			serverErr(w, "owner_namespace_info_failed")
			return
		}
	}

	hasOrg := resp.Org != nil && strings.TrimSpace(resp.Org.ID) != ""
	hasUser := resp.User != nil && strings.TrimSpace(resp.User.ID) != ""
	switch {
	case hasOrg && hasUser:
		resp.Exists = true
		resp.EntityKind = "org_and_user"
	case hasOrg:
		resp.Exists = true
		resp.EntityKind = "org"
	case hasUser:
		resp.Exists = true
		resp.EntityKind = "user"
		if resp.State == "unregistered" {
			resp.State = ownerNamespaceStateRegisteredUser
		}
	default:
		resp.Exists = false
		resp.EntityKind = "none"
	}

	writeJSON(w, http.StatusOK, resp)
}

func normalizeAdminAccountKind(kind string) string {
	return strings.ToLower(strings.TrimSpace(kind))
}

func (s *Service) handleAdminAccountParkPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	var req struct {
		Kind string `json:"kind"`
		Slug string `json:"slug"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Slug) == "" {
		badRequest(w, "invalid_request")
		return
	}
	switch normalizeAdminAccountKind(req.Kind) {
	case adminAccountKindOrg:
		orgID, created, err := s.svc.ParkOrgNamespace(r.Context(), req.Slug)
		if err != nil {
			switch {
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
			"kind":    adminAccountKindOrg,
			"org_id":  strings.TrimSpace(orgID),
			"created": created,
			"state":   string(core.OwnerNamespaceStateParkedOrg),
		})
		return
	case adminAccountKindUser:
		userID, orgID, created, err := s.svc.ParkUserNamespace(r.Context(), req.Slug)
		if err != nil {
			switch {
			case errors.Is(err, core.ErrReservedAccountNotFound):
				notFound(w, "reserved_account_not_found")
			case errors.Is(err, core.ErrUserNotFound):
				notFound(w, "user_not_found")
			case errors.Is(err, core.ErrOwnerSlugTaken):
				sendErr(w, http.StatusConflict, "owner_slug_taken")
			case errors.Is(err, core.ErrReservedAccountClaimed):
				sendErr(w, http.StatusConflict, "account_already_claimed")
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
			"kind":    adminAccountKindUser,
			"user_id": strings.TrimSpace(userID),
			"org_id":  strings.TrimSpace(orgID),
			"created": created,
			"state":   ownerNamespaceStateParkedUser,
		})
		return
	default:
		badRequest(w, "invalid_request")
		return
	}
}

func (s *Service) handleAdminAccountClaimPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	var req struct {
		Kind      string `json:"kind"`
		Slug      string `json:"slug"`
		OwnerUser string `json:"owner_user_id,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Slug) == "" {
		badRequest(w, "invalid_request")
		return
	}
	switch normalizeAdminAccountKind(req.Kind) {
	case adminAccountKindOrg:
		if strings.TrimSpace(req.OwnerUser) == "" {
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
			"kind":    adminAccountKindOrg,
			"org_id":  strings.TrimSpace(orgID),
			"state":   string(core.OwnerNamespaceStateRegistered),
			"created": created,
		})
		return
	case adminAccountKindUser:
		userID, orgID, created, err := s.svc.ClaimUserNamespace(r.Context(), req.Slug)
		if err != nil {
			switch {
			case errors.Is(err, core.ErrUserNotFound):
				notFound(w, "user_not_found")
			case errors.Is(err, core.ErrOwnerSlugTaken):
				sendErr(w, http.StatusConflict, "owner_slug_taken")
			case errors.Is(err, core.ErrReservedAccountClaimed):
				sendErr(w, http.StatusConflict, "account_already_claimed")
			case errors.Is(err, core.ErrInvalidOwnerNamespaceTransition):
				sendErr(w, http.StatusConflict, "invalid_owner_namespace_transition")
			case errors.Is(err, core.ErrInvalidOrgSlug):
				badRequest(w, "invalid_slug")
			default:
				serverErr(w, "account_claim_user_failed")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"kind":    adminAccountKindUser,
			"user_id": strings.TrimSpace(userID),
			"org_id":  strings.TrimSpace(orgID),
			"state":   ownerNamespaceStateRegisteredUser,
			"created": created,
		})
		return
	default:
		badRequest(w, "invalid_request")
		return
	}
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
