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
	OK            bool                          `json:"ok"`
	RequestedSlug string                        `json:"requested_slug"`
	Slug          string                        `json:"slug"`
	Renamed       bool                          `json:"renamed"`
	HoldUntil     *time.Time                    `json:"hold_until,omitempty"`
	Claimable     ownerNamespaceClaimableInfo   `json:"claimable"`
	Org           *ownerNamespaceOrgPublicInfo  `json:"org,omitempty"`
	User          *ownerNamespaceUserPublicInfo `json:"user,omitempty"`
}

type ownerNamespaceClaimableInfo struct {
	User bool `json:"user"`
	Org  bool `json:"org"`
}

func (s *Service) handleOwnerNamespaceInfoGET(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(r.PathValue("slug"))
	if slug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	lookup, err := s.svc.LookupOwnerNamespace(r.Context(), slug)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrInvalidOrgSlug):
			badRequest(w, ErrInvalidSlug)
			return
		default:
			serverErr(w, ErrOwnerNamespaceInfoFailed)
			return
		}
	}

	resp := ownerNamespaceLookupResponse{
		OK:            true,
		RequestedSlug: strings.TrimSpace(lookup.RequestedSlug),
		Slug:          strings.TrimSpace(lookup.CanonicalSlug),
		Renamed:       lookup.Renamed,
		HoldUntil:     lookup.HoldUntil,
		Claimable: ownerNamespaceClaimableInfo{
			User: lookup.Claimable && lookup.User == nil,
			Org:  lookup.Claimable && lookup.Org == nil,
		},
	}
	if lookup.Org != nil {
		resp.Org = &ownerNamespaceOrgPublicInfo{
			ID:          strings.TrimSpace(lookup.Org.ID),
			Slug:        strings.TrimSpace(lookup.Org.Slug),
			IsPersonal:  lookup.Org.IsPersonal,
			OwnerUserID: strings.TrimSpace(lookup.Org.OwnerUserID),
			State:       string(lookup.Org.State),
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
		badRequest(w, ErrInvalidRequest)
		return
	}
	switch normalizeAdminAccountKind(req.Kind) {
	case adminAccountKindOrg:
		orgID, created, err := s.svc.ParkOrgNamespace(r.Context(), req.Slug)
		if err != nil {
			switch {
			case errors.Is(err, core.ErrOwnerSlugTaken):
				sendErr(w, http.StatusConflict, ErrOwnerSlugTaken)
			case errors.Is(err, core.ErrInvalidOwnerNamespaceTransition):
				sendErr(w, http.StatusConflict, ErrInvalidOwnerNamespaceTransition)
			case errors.Is(err, core.ErrInvalidOrgSlug):
				badRequest(w, ErrInvalidSlug)
			default:
				serverErr(w, ErrAccountParkFailed)
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
				notFound(w, ErrReservedAccountNotFound)
			case errors.Is(err, core.ErrUserNotFound):
				notFound(w, ErrUserNotFound)
			case errors.Is(err, core.ErrOwnerSlugTaken):
				sendErr(w, http.StatusConflict, ErrOwnerSlugTaken)
			case errors.Is(err, core.ErrReservedAccountClaimed):
				sendErr(w, http.StatusConflict, ErrAccountAlreadyClaimed)
			case errors.Is(err, core.ErrInvalidOwnerNamespaceTransition):
				sendErr(w, http.StatusConflict, ErrInvalidOwnerNamespaceTransition)
			case errors.Is(err, core.ErrInvalidOrgSlug):
				badRequest(w, ErrInvalidSlug)
			default:
				serverErr(w, ErrAccountParkFailed)
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
		badRequest(w, ErrInvalidRequest)
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
		badRequest(w, ErrInvalidRequest)
		return
	}
	switch normalizeAdminAccountKind(req.Kind) {
	case adminAccountKindOrg:
		if strings.TrimSpace(req.OwnerUser) == "" {
			badRequest(w, ErrInvalidRequest)
			return
		}
		orgID, created, err := s.svc.ClaimOrgNamespace(r.Context(), req.Slug, req.OwnerUser)
		if err != nil {
			switch {
			case errors.Is(err, core.ErrUserNotFound):
				notFound(w, ErrOwnerUserNotFound)
			case errors.Is(err, core.ErrOwnerMembershipRequired):
				badRequest(w, ErrOwnerMembershipRequired)
			case errors.Is(err, core.ErrOwnerNamespaceAlreadyClaimed):
				sendErr(w, http.StatusConflict, ErrOrgAlreadyClaimed)
			case errors.Is(err, core.ErrOwnerSlugTaken):
				sendErr(w, http.StatusConflict, ErrOwnerSlugTaken)
			case errors.Is(err, core.ErrInvalidOwnerNamespaceTransition):
				sendErr(w, http.StatusConflict, ErrInvalidOwnerNamespaceTransition)
			case errors.Is(err, core.ErrInvalidOrgSlug):
				badRequest(w, ErrInvalidSlug)
			default:
				serverErr(w, ErrAccountClaimOrgFailed)
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
				notFound(w, ErrUserNotFound)
			case errors.Is(err, core.ErrOwnerSlugTaken):
				sendErr(w, http.StatusConflict, ErrOwnerSlugTaken)
			case errors.Is(err, core.ErrReservedAccountClaimed):
				sendErr(w, http.StatusConflict, ErrAccountAlreadyClaimed)
			case errors.Is(err, core.ErrInvalidOwnerNamespaceTransition):
				sendErr(w, http.StatusConflict, ErrInvalidOwnerNamespaceTransition)
			case errors.Is(err, core.ErrInvalidOrgSlug):
				badRequest(w, ErrInvalidSlug)
			default:
				serverErr(w, ErrAccountClaimUserFailed)
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
		badRequest(w, ErrInvalidRequest)
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
		badRequest(w, ErrInvalidRequest)
		return
	}

	restricted, alreadyRestricted, err := s.svc.RestrictOwnerNamespaceSlugs(r.Context(), req.Slugs)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrInvalidOrgSlug):
			badRequest(w, ErrInvalidSlug)
		case errors.Is(err, core.ErrOwnerNamespaceBatchEmpty):
			badRequest(w, ErrInvalidRequest)
		case errors.Is(err, core.ErrOwnerSlugTaken):
			sendErr(w, http.StatusConflict, ErrOwnerSlugTaken)
		default:
			serverErr(w, ErrAccountRestrictFailed)
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
		badRequest(w, ErrInvalidRequest)
		return
	}

	unrestricted, notRestricted, err := s.svc.UnrestrictOwnerNamespaceSlugs(r.Context(), req.Slugs)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrInvalidOrgSlug):
			badRequest(w, ErrInvalidSlug)
		case errors.Is(err, core.ErrOwnerNamespaceBatchEmpty):
			badRequest(w, ErrInvalidRequest)
		default:
			serverErr(w, ErrAccountUnrestrictFailed)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"unrestricted":   unrestricted,
		"not_restricted": notRestricted,
	})
}
