package httpapi

import (
	"net/http"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/verify"
)

type PersonalTokenCreateRequest struct {
	Name        string     `json:"name"`
	GroupID     string     `json:"group_id"`
	Permissions []string   `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

func (s *Service) handlePersonalTokensGET(w http.ResponseWriter, r *http.Request) {
	who, ok := verify.IdentityFromContext(r.Context())
	if !ok {
		s.fail(w, errmodel.CodeUnauthenticated)
		return
	}
	page, ok := s.readPage(w, r)
	if !ok {
		return
	}
	out, err := s.svc.ListPersonalAccessTokens(r.Context(), who, page)
	if err != nil {
		s.writeError(w, err)
		return
	}
	list(w, out)
}

func (s *Service) handlePersonalTokensPOST(w http.ResponseWriter, r *http.Request) {
	who, ok := verify.IdentityFromContext(r.Context())
	if !ok {
		s.fail(w, errmodel.CodeUnauthenticated)
		return
	}
	var body PersonalTokenCreateRequest
	if err := decodeJSON(r, &body); err != nil {
		s.fail(w, errmodel.CodeInvalidRequest)
		return
	}
	out, err := s.svc.CreatePersonalAccessToken(r.Context(), who, iam.NewPersonalAccessToken{Name: body.Name, GroupID: body.GroupID, Permissions: ident.Perms(body.Permissions), ExpiresAt: body.ExpiresAt})
	if err != nil {
		s.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Service) handlePersonalTokensDELETE(w http.ResponseWriter, r *http.Request) {
	who, ok := verify.IdentityFromContext(r.Context())
	if !ok {
		s.fail(w, errmodel.CodeUnauthenticated)
		return
	}
	if err := s.svc.RevokePersonalAccessToken(r.Context(), who, r.PathValue("id")); err != nil {
		s.writeError(w, err)
		return
	}
	noContent(w)
}
