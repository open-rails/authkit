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
	userID, orgID, reserved, err := s.svc.ReserveAccount(r.Context(), req.Slug, "", "", "")
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

func (s *Service) handleAdminAccountsClaimPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	var req struct {
		Slug     string  `json:"slug"`
		Password string  `json:"password"`
		Email    *string `json:"email,omitempty"`
		Phone    *string `json:"phone,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Slug) == "" || strings.TrimSpace(req.Password) == "" {
		badRequest(w, "invalid_request")
		return
	}
	userID, orgID, err := s.svc.ClaimReservedAccount(r.Context(), req.Slug, req.Password, req.Email, req.Phone)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrReservedAccountNotFound):
			notFound(w, "reserved_account_not_found")
		case errors.Is(err, core.ErrReservedAccountClaimed):
			sendErr(w, http.StatusConflict, "account_already_claimed")
		case errors.Is(err, core.ErrInvalidOrgSlug):
			badRequest(w, "invalid_slug")
		default:
			badRequest(w, "account_claim_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"user_id":  strings.TrimSpace(userID),
		"org_id":   strings.TrimSpace(orgID),
		"reserved": false,
	})
}
