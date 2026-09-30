package httpapi

// Invite-link handlers of the group surface.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// groupInviteLinkMint mints a link issued by the caller; the code is returned once.
func (s *Service) groupInviteLinkMint(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor) {
	if s.rateLimited(w, r, RLInviteCreate) {
		return
	}
	var body InvitationCreateRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	role, err := s.groupRole(g.Persona, body.Role)
	if err != nil {
		writeError(w, err)
		return
	}
	created, err := s.svc.CreateInvitation(r.Context(), actor, iam.GroupByID(g.ID), iam.NewInvitation{Role: role, ExpiresAt: body.ExpiresAt})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created) // the code is shown once
}

// groupInviteLinkList lists the group's links, newest first (?cursor=,
// ?limit=), never their codes.
func (s *Service) groupInviteLinkList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	p, ok := readPage(w, r)
	if !ok {
		return
	}
	page, err := s.svc.ListInvitations(r.Context(), iam.GroupByID(g.ID), p)
	if err != nil {
		writeError(w, err)
		return
	}
	links := page.Items[:0:0]
	for _, inv := range page.Items {
		if inv.Email == nil { // an email invitation is not a link
			links = append(links, inv)
		}
	}
	page.Items = links
	list(w, page)
}

// groupInviteLinkRevoke revokes the group's link {link}; a revoked or unknown
// link answers 204 too.
func (s *Service) groupInviteLinkRevoke(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor, linkID string) {
	if linkID == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.RevokeInvitation(r.Context(), actor, iam.GroupByID(g.ID), linkID); err != nil && !errors.Is(err, iam.ErrInvitationNotFound) {
		writeError(w, err)
		return
	}
	noContent(w)
}

// handleInviteRedeemPOST redeems an invite-link code for the signed-in user,
// assigning the link's role. Persona-agnostic: the code resolves to its own
// group, so one endpoint serves every persona.
func (s *Service) handleInviteRedeemPOST(w http.ResponseWriter, r *http.Request) {
	actor, ok := verify.ActorFromContext(r.Context())
	if !ok || actor.Kind() != iam.ActorUser {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	var body InviteRedeemRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Code) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	res, err := s.svc.RedeemInvitation(r.Context(), actor, strings.TrimSpace(body.Code))
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
