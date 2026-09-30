package httpapi

// API-key handlers of the group surface.

import (
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// apiKeyMintRequest is the body for POST /groups/{group_id}/api-keys:
// the one group role the key holds, and an optional expiry.
type apiKeyMintRequest struct {
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// apiKeyJSON is a key's metadata on the wire (never its secret).
func apiKeyJSON(k iam.APIKey) map[string]any {
	m := map[string]any{
		"id":          k.ID,
		"lookup_id":   k.LookupID,
		"name":        k.Name,
		"role":        k.Role.String(),
		"permissions": k.Permissions,
		"created_at":  k.CreatedAt,
	}
	if k.CreatedBy != "" {
		m["created_by"] = k.CreatedBy
	}
	if k.LastUsedAt != nil {
		m["last_used_at"] = k.LastUsedAt
	}
	if k.ExpiresAt != nil {
		m["expires_at"] = k.ExpiresAt
	}
	if k.RevokedAt != nil {
		m["revoked_at"] = k.RevokedAt
	}
	return m
}

// groupAPIKeyMint mints a key created by the caller and returns its token
// once, as "secret".
func (s *Service) groupAPIKeyMint(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor) {
	if s.rateLimited(w, r, RLAPIKeyMint) {
		return
	}
	var body apiKeyMintRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	role, err := s.groupRole(g.Persona, body.Role)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	created, err := s.svc.CreateAPIKey(r.Context(), actor, iam.GroupByID(g.ID), iam.NewAPIKey{
		Name:      strings.TrimSpace(body.Name),
		Role:      role,
		ExpiresAt: body.ExpiresAt,
	})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	out := apiKeyJSON(created.APIKey)
	out["secret"] = created.Secret // shown once
	writeJSON(w, http.StatusCreated, out)
}

// groupAPIKeyList lists the group's keys, newest first (?cursor=, ?limit=).
func (s *Service) groupAPIKeyList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	page, err := s.svc.ListAPIKeys(r.Context(), iam.GroupByID(g.ID), pageQuery(r))
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(page.Items))
	for _, k := range page.Items {
		data = append(data, apiKeyJSON(k))
	}
	writeList(w, data, page.Next)
}

// groupAPIKeyRevoke revokes the group's key (the :key path param). Revoking a
// revoked key succeeds; 404 when no key has the id in this group.
func (s *Service) groupAPIKeyRevoke(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor, id string) {
	if id == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.RevokeAPIKey(r.Context(), actor, iam.GroupByID(g.ID), id); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
