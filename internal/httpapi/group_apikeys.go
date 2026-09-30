package httpapi

// API-key handlers of the group surface.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// groupAPIKeyMint mints a key created by the caller and returns its token
// once, as "secret".
func (s *Service) groupAPIKeyMint(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor) {
	if s.rateLimited(w, r, RLAPIKeyCreate) {
		return
	}
	var body APIKeyCreateRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	role, err := s.groupRole(g.Persona, body.Role)
	if err != nil {
		writeError(w, err)
		return
	}
	created, err := s.svc.CreateAPIKey(r.Context(), actor, iam.GroupByID(g.ID), iam.NewAPIKey{
		Name:      strings.TrimSpace(body.Name),
		Role:      role,
		ExpiresAt: body.ExpiresAt,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created) // the secret is shown once
}

// groupAPIKeyList lists the group's keys, newest first (?cursor=, ?limit=).
func (s *Service) groupAPIKeyList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	p, ok := readPage(w, r)
	if !ok {
		return
	}
	page, err := s.svc.ListAPIKeys(r.Context(), iam.GroupByID(g.ID), p)
	if err != nil {
		writeError(w, err)
		return
	}
	list(w, page)
}

// groupAPIKeyRevoke revokes the group's key {id}. Like every DELETE it is
// idempotent: a revoked or unknown key answers 204 too.
func (s *Service) groupAPIKeyRevoke(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor, id string) {
	if id == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.RevokeAPIKey(r.Context(), actor, iam.GroupByID(g.ID), id); err != nil && !errors.Is(err, iam.ErrAPIKeyNotFound) {
		writeError(w, err)
		return
	}
	noContent(w)
}
