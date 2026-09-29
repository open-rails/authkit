package httpapi

// Invite-link handlers of the group surface.

import (
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// inviteLinkCreateRequest is the body for POST /groups/{group_id}/invites/links.
// role is required; expires_in_seconds overrides the default lifetime.
type inviteLinkCreateRequest struct {
	Role             string `json:"role"`
	ExpiresInSeconds *int64 `json:"expires_in_seconds,omitempty"`
}

// groupInviteLinkMint mints a link issued by the caller; the code is returned once.
func (s *Service) groupInviteLinkMint(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor) {
	if s.rateLimited(w, r, RLInviteCreate) {
		return
	}
	var body inviteLinkCreateRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	role, err := s.svc.PermissionGroupSchema().ParseRole(g.Persona, body.Role)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	l := iam.NewInviteLink{Role: role}
	if body.ExpiresInSeconds != nil && *body.ExpiresInSeconds > 0 {
		l.ExpiresIn = time.Duration(*body.ExpiresInSeconds) * time.Second
	}
	created, err := s.svc.CreateInviteLink(r.Context(), actor, iam.GroupByID(g.ID), l)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         created.ID,
		"code":       created.Code, // shown once
		"url":        created.URL,
		"expires_at": created.ExpiresAt,
	})
}

// groupInviteLinkList lists the group's links, newest first (?cursor=,
// ?limit=), never their codes.
func (s *Service) groupInviteLinkList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	page, err := s.svc.InviteLinks(r.Context(), iam.GroupByID(g.ID), pageQuery(r))
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(page.Items))
	for _, l := range page.Items {
		m := map[string]any{
			"id":         l.ID,
			"role":       l.Role.Name(),
			"created_at": l.CreatedAt,
		}
		if l.InvitedBy != "" {
			m["invited_by"] = l.InvitedBy
		}
		if l.RedeemedAt != nil {
			m["redeemed_at"] = l.RedeemedAt
		}
		if l.ExpiresAt != nil {
			m["expires_at"] = l.ExpiresAt
		}
		if l.RevokedAt != nil {
			m["revoked_at"] = l.RevokedAt
		}
		data = append(data, m)
	}
	writeList(w, data, page.Next)
}

// groupInviteLinkRevoke revokes a link by id (the :link path param), scoped to this group.
func (s *Service) groupInviteLinkRevoke(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor, linkID string) {
	if linkID == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.RevokeInviteLink(r.Context(), actor, iam.GroupByID(g.ID), linkID); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// inviteRedeemRequest is the body for POST /invites/redeem.
type inviteRedeemRequest struct {
	Code string `json:"code"`
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
	var body inviteRedeemRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Code) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	res, err := s.svc.RedeemInviteLink(r.Context(), actor, strings.TrimSpace(body.Code))
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"group_id": res.GroupID,
		"persona":  res.Persona,
		"role":     res.Role.Name(),
	})
}
