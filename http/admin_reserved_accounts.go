package authhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

const ownerNamespaceStateRegisteredUser = "registered_user"
const ownerNamespaceStateParkedUser = "parked_user"

const (
	adminAccountKindTenant = "tenant"
	adminAccountKindUser   = "user"
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
	OK            bool                          `json:"ok"`
	Slug          string                        `json:"slug"`
	RequestedSlug string                        `json:"requested_slug"`
	CanonicalSlug string                        `json:"canonical_slug"`
	State         string                        `json:"state"`
	Status        string                        `json:"status"`
	Claimable     bool                          `json:"claimable"`
	Exists        bool                          `json:"exists"`
	EntityKind    string                        `json:"entity_kind"`
	Renamed       bool                          `json:"renamed"`
	HoldUntil     *time.Time                    `json:"hold_until,omitempty"`
	Tenant        *ownerNamespaceOrgPublicInfo  `json:"tenant,omitempty"`
	User          *ownerNamespaceUserPublicInfo `json:"user,omitempty"`
}

func (s *Service) handleOwnerNamespaceInfoGET(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(r.PathValue("slug"))
	if slug == "" {
		badRequest(w, "invalid_request")
		return
	}

	lookup, err := s.svc.LookupOwnerNamespace(r.Context(), slug)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrInvalidTenantSlug):
			badRequest(w, "invalid_slug")
			return
		default:
			serverErr(w, "owner_namespace_info_failed")
			return
		}
	}

	resp := ownerNamespaceLookupResponse{
		OK:            true,
		Slug:          strings.TrimSpace(lookup.CanonicalSlug),
		RequestedSlug: strings.TrimSpace(lookup.RequestedSlug),
		CanonicalSlug: strings.TrimSpace(lookup.CanonicalSlug),
		State:         string(lookup.Status),
		Status:        string(lookup.Status),
		Claimable:     lookup.Claimable,
		Exists:        lookup.Exists,
		EntityKind:    strings.TrimSpace(lookup.EntityKind),
		Renamed:       lookup.Renamed,
		HoldUntil:     lookup.HoldUntil,
	}
	if lookup.Tenant != nil {
		resp.Tenant = &ownerNamespaceOrgPublicInfo{
			ID:          strings.TrimSpace(lookup.Tenant.ID),
			Slug:        strings.TrimSpace(lookup.Tenant.Slug),
			IsPersonal:  lookup.Tenant.IsPersonal,
			OwnerUserID: strings.TrimSpace(lookup.Tenant.OwnerUserID),
			State:       string(lookup.Tenant.State),
		}
	}
	if lookup.User != nil {
		resp.User = &ownerNamespaceUserPublicInfo{
			ID:       strings.TrimSpace(lookup.User.ID),
			Username: strings.TrimSpace(lookup.User.Username),
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func normalizeAdminAccountKind(kind string) string {
	return strings.ToLower(strings.TrimSpace(kind))
}

func (s *Service) handleAdminAccountParkPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLAdminRolesGrant) {
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
	case adminAccountKindTenant:
		tenantID, created, err := s.svc.ParkOrgNamespace(r.Context(), req.Slug)
		if err != nil {
			switch {
			case errors.Is(err, core.ErrOwnerSlugTaken):
				sendErr(w, http.StatusConflict, "owner_slug_taken")
			case errors.Is(err, core.ErrInvalidOwnerNamespaceTransition):
				sendErr(w, http.StatusConflict, "invalid_owner_namespace_transition")
			case errors.Is(err, core.ErrInvalidTenantSlug):
				badRequest(w, "invalid_slug")
			default:
				serverErr(w, "account_park_failed")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"kind":      adminAccountKindTenant,
			"tenant_id": strings.TrimSpace(tenantID),
			"created":   created,
			"state":     string(core.OwnerNamespaceStateParkedTenant),
		})
		return
	case adminAccountKindUser:
		userID, tenantID, created, err := s.svc.ParkUserNamespace(r.Context(), req.Slug)
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
			case errors.Is(err, core.ErrInvalidTenantSlug):
				badRequest(w, "invalid_slug")
			default:
				serverErr(w, "account_park_failed")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"kind":      adminAccountKindUser,
			"user_id":   strings.TrimSpace(userID),
			"tenant_id": strings.TrimSpace(tenantID),
			"created":   created,
			"state":     ownerNamespaceStateParkedUser,
		})
		return
	default:
		badRequest(w, "invalid_request")
		return
	}
}

func (s *Service) handleAdminAccountClaimPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLAdminRolesGrant) {
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
	case adminAccountKindTenant:
		if strings.TrimSpace(req.OwnerUser) == "" {
			badRequest(w, "invalid_request")
			return
		}
		tenantID, created, err := s.svc.ClaimOrgNamespace(r.Context(), req.Slug, req.OwnerUser)
		if err != nil {
			switch {
			case errors.Is(err, core.ErrUserNotFound):
				notFound(w, "owner_user_not_found")
			case errors.Is(err, core.ErrOwnerMembershipRequired):
				badRequest(w, "owner_membership_required")
			case errors.Is(err, core.ErrOwnerNamespaceAlreadyClaimed):
				sendErr(w, http.StatusConflict, "tenant_already_claimed")
			case errors.Is(err, core.ErrOwnerSlugTaken):
				sendErr(w, http.StatusConflict, "owner_slug_taken")
			case errors.Is(err, core.ErrInvalidOwnerNamespaceTransition):
				sendErr(w, http.StatusConflict, "invalid_owner_namespace_transition")
			case errors.Is(err, core.ErrInvalidTenantSlug):
				badRequest(w, "invalid_slug")
			default:
				serverErr(w, "account_claim_tenant_failed")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"kind":      adminAccountKindTenant,
			"tenant_id": strings.TrimSpace(tenantID),
			"state":     string(core.OwnerNamespaceStateRegistered),
			"created":   created,
		})
		return
	case adminAccountKindUser:
		userID, tenantID, created, err := s.svc.ClaimUserNamespace(r.Context(), req.Slug)
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
			case errors.Is(err, core.ErrInvalidTenantSlug):
				badRequest(w, "invalid_slug")
			default:
				serverErr(w, "account_claim_user_failed")
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"kind":      adminAccountKindUser,
			"user_id":   strings.TrimSpace(userID),
			"tenant_id": strings.TrimSpace(tenantID),
			"state":     ownerNamespaceStateRegisteredUser,
			"created":   created,
		})
		return
	default:
		badRequest(w, "invalid_request")
		return
	}
}

func (s *Service) handleAdminAccountsRestrictPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLAdminRolesGrant) {
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
		case errors.Is(err, core.ErrInvalidTenantSlug):
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
	if s.rateLimited(w, r, RLAdminRolesGrant) {
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
		case errors.Is(err, core.ErrInvalidTenantSlug):
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
