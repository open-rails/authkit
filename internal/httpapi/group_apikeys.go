package httpapi

// API-key handlers of the generated per-persona group surface.

import (
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// apiKeyMintRequest is the body for POST /<persona>/<instance_slug>/api-keys. Role
// is required (the single group role the key holds); the key's scope is the
// addressed permission-group instance plus that role's permissions.
type apiKeyMintRequest struct {
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// groupAPIKeyMint mints a new API key for the group, returning the plaintext
// secret ONCE (it is never recoverable afterward). The created-by attribution is
// the authenticated caller.
func (s *Service) groupAPIKeyMint(w http.ResponseWriter, r *http.Request, group iam.GroupRef, createdBy string) {
	var body apiKeyMintRequest
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	key, secret, err := s.svc.MintAPIKey(r.Context(), group, iam.APIKeyMintOptions{
		Name:      strings.TrimSpace(body.Name),
		Role:      iam.Role(strings.TrimSpace(body.Role)),
		CreatedBy: createdBy,
		ExpiresAt: body.ExpiresAt,
	})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          key.ID,
		"key_id":      key.KeyID,
		"name":        key.Name,
		"role":        key.Role,
		"permissions": key.Permissions,
		"secret":      secret, // shown ONCE
	})
}

// groupAPIKeyList lists the group's API keys. The secret is NEVER returned here
// (only on mint).
func (s *Service) groupAPIKeyList(w http.ResponseWriter, r *http.Request, group iam.GroupRef) {
	keys, err := s.svc.ListAPIKeys(r.Context(), group)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		m := map[string]any{
			"id":          k.ID,
			"key_id":      k.KeyID,
			"name":        k.Name,
			"role":        k.Role,
			"permissions": k.Permissions,
			"created_at":  k.CreatedAt,
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
		data = append(data, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":        "list",
		"persona":       group.Persona,
		"instance_slug": group.Instance,
		"data":          data,
	})
}

// groupAPIKeyRevoke revokes the group's API key by token id (the :key path
// param). 404 if no matching, not-already-revoked key exists in this group.
func (s *Service) groupAPIKeyRevoke(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor verify.Claims, tokenID string) {
	if tokenID == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	ok, err := s.svc.RevokeAPIKeyFromClaims(r.Context(), actor, group, tokenID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	if !ok {
		notFound(w, iam.CodeNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": tokenID})
}
