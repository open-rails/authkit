package httpapi

// Invitation handlers of the group surface: invite links and emailed
// invitations are one resource.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

// groupInvitationCreate makes an invite link (no email), whose code is
// answered once (201), or emails an invitation (202). The 202 is the same for
// every address, so it never reveals whether an account holds it; the role
// lands only when the recipient registers with it, or redeems it signed in to
// the account that proved the address. On root, an email with no role
// invites someone to register (root:users:invite).
func (s *Service) groupInvitationCreate(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	var body InvitationCreateRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	n := iam.NewInvitation{ExpiresAt: body.ExpiresAt}
	if text := strings.TrimSpace(body.Role); text != "" {
		role, err := s.groupRole(g.Persona, text)
		if err != nil {
			writeError(w, err)
			return
		}
		n.Role = role
	}
	if strings.TrimSpace(body.Email) == "" {
		if n.Role.IsZero() {
			fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("role"))
			return
		}
		created, err := s.svc.CreateInvitation(r.Context(), who, iam.GroupByID(g.ID), n)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, created)
		return
	}
	n.Email = contact.NormalizeEmail(body.Email)
	if err := contact.ValidateEmail(n.Email); err != nil {
		writeError(w, err)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLInviteCreate, n.Email) {
		return
	}
	if _, err := s.svc.CreateInvitation(r.Context(), who, iam.GroupByID(g.ID), n); err != nil {
		writeError(w, err)
		return
	}
	accepted(w)
}

// groupInvitationsList lists the group's links and email invitations,
// newest first (?cursor=, ?limit=), never their codes.
func (s *Service) groupInvitationsList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	p, ok := readPage(w, r)
	if !ok {
		return
	}
	page, err := s.svc.ListInvitations(r.Context(), iam.GroupByID(g.ID), p)
	if err != nil {
		writeError(w, err)
		return
	}
	list(w, page)
}

// groupInvitationRevoke revokes the group's invitation {id}; a revoked,
// redeemed or unknown one answers 204 too.
func (s *Service) groupInvitationRevoke(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity, id string) {
	if err := s.svc.RevokeInvitation(r.Context(), who, iam.GroupByID(g.ID), id); err != nil && !errors.Is(err, iam.ErrInvitationNotFound) {
		writeError(w, err)
		return
	}
	noContent(w)
}

// handleInvitationRedeemPOST redeems an invitation's code for the signed-in
// user, assigning its role (an emailed one only to the account that proved
// its address). Persona-agnostic: the code resolves to its own group.
func (s *Service) handleInvitationRedeemPOST(w http.ResponseWriter, r *http.Request) {
	who, ok := verify.IdentityFromContext(r.Context())
	if !ok || !state(who).IsUser() {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	var body InvitationRedeemRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Code) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	res, err := s.svc.RedeemInvitation(r.Context(), who, strings.TrimSpace(body.Code))
	if err != nil {
		writeError(w, err)
		return
	}
	g, err := s.svc.Group(r.Context(), iam.GroupByID(res.GroupID))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, iam.Membership{Group: g, Role: res.Role})
}
