package httpapi

// Invite-link handlers of the generated per-persona group surface.

import (
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// inviteLinkCreateRequest is the body for POST /<persona>/<instance_slug>/invites/links.
// role is required; expires_in_seconds overrides the default lifetime.
type inviteLinkCreateRequest struct {
	Role             string `json:"role"`
	ExpiresInSeconds *int64 `json:"expires_in_seconds,omitempty"`
}

// groupInviteLinkMint mints an invite link; the plaintext code is returned ONCE.
func (s *Service) groupInviteLinkMint(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor) {
	if s.rateLimited(w, r, RLInviteCreate) {
		return
	}
	var body inviteLinkCreateRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	invitedBy, ok := userActorID(w, actor)
	if !ok {
		return
	}
	req := iam.CreateGroupInviteLinkRequest{
		Persona:      group.Persona(),
		InstanceSlug: group.Slug(),
		Role:         iam.Role(strings.TrimSpace(body.Role)),
		InvitedBy:    invitedBy,
	}
	if body.ExpiresInSeconds != nil && *body.ExpiresInSeconds > 0 {
		req.ExpiresIn = time.Duration(*body.ExpiresInSeconds) * time.Second
	}
	created, err := s.svc.CreateGroupInviteLink(r.Context(), req)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":   created.ID,
		"code": created.Code, // shown ONCE
		"url":  created.URL,
	})
}

// groupInviteLinkList lists the group's invite links (never returns the code).
func (s *Service) groupInviteLinkList(w http.ResponseWriter, r *http.Request, group iam.GroupRef, _ iam.Actor) {
	links, err := s.svc.ListGroupInviteLinks(r.Context(), group)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(links))
	for _, l := range links {
		m := map[string]any{
			"id":         l.ID,
			"role":       l.Role,
			"invited_by": l.InvitedBy,
			"created_at": l.CreatedAt,
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
	writeJSON(w, http.StatusOK, map[string]any{
		"object":        "list",
		"persona":       group.Persona(),
		"instance_slug": group.Slug(),
		"data":          data,
	})
}

// groupInviteLinkRevoke revokes a link by id (the :link path param), scoped to this group.
func (s *Service) groupInviteLinkRevoke(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor, linkID string) {
	if linkID == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	if err := s.svc.RevokeGroupInviteLinkForActor(r.Context(), actor, group, linkID); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": linkID})
}

// inviteRedeemRequest is the body for POST /invites/redeem.
type inviteRedeemRequest struct {
	Code string `json:"code"`
}

// handleInviteRedeemPOST redeems an invite-link code for the authenticated caller,
// assigning the link's role. Persona-agnostic: the code resolves to its own group,
// so one endpoint serves every persona.
func (s *Service) handleInviteRedeemPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, iam.CodeNotAuthenticated)
		return
	}
	var body inviteRedeemRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Code) == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	res, err := s.svc.RedeemGroupInviteLink(r.Context(), strings.TrimSpace(body.Code), claims.UserID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       res.Persona,
		"instance_slug": res.InstanceSlug,
		"role":          res.Role,
	})
}
