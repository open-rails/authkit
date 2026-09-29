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
		"role":        k.Role,
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
	var body apiKeyMintRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	key, token, err := s.svc.MintAPIKey(r.Context(), actor, iam.GroupByID(g.ID), iam.NewAPIKey{
		Name:      strings.TrimSpace(body.Name),
		Role:      iam.Role(strings.TrimSpace(body.Role)),
		ExpiresAt: body.ExpiresAt,
	})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	out := apiKeyJSON(key)
	out["secret"] = token // shown once
	writeJSON(w, http.StatusCreated, out)
}

// groupAPIKeyList lists the group's keys, newest first (?cursor=, ?limit=).
func (s *Service) groupAPIKeyList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	page, err := s.svc.APIKeys(r.Context(), iam.GroupByID(g.ID), pageQuery(r))
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

// groupAPIKeyRevoke revokes the group's key (the :key path param). 404 when no
// live key matches in this group.
func (s *Service) groupAPIKeyRevoke(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor, id string) {
	if id == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	ok, err := s.svc.RevokeAPIKey(r.Context(), actor, iam.GroupByID(g.ID), id)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	if !ok {
		fail(w, errmodel.CodeNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}
