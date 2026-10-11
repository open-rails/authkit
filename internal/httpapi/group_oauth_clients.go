package httpapi

// A group's OAuth clients (#450): /groups/{group_id}/oauth-clients, under
// <persona>:credentials:read and :manage, changes with a recent sign-in.

import (
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

// OAuthClientSecret is a rotated client secret, shown this once.
type OAuthClientSecret struct {
	ClientSecret string `json:"client_secret"`
}

func (s *Service) groupOAuthClientsList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	clients, err := s.svc.GroupOAuthClients(r.Context(), iam.GroupByID(g.ID))
	if err != nil {
		writeError(w, err)
		return
	}
	all(w, clients)
}

func (s *Service) groupOAuthClientGet(w http.ResponseWriter, r *http.Request, g iam.Group) {
	c, err := s.svc.GroupOAuthClient(r.Context(), iam.GroupByID(g.ID), r.PathValue("client_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Service) groupOAuthClientCreate(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	var body iam.NewOAuthClient
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	out, err := s.svc.CreateGroupOAuthClient(r.Context(), who, iam.GroupByID(g.ID), body)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Service) groupOAuthClientUpdate(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	var body iam.OAuthClientUpdate
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	out, err := s.svc.UpdateGroupOAuthClient(r.Context(), who, iam.GroupByID(g.ID), r.PathValue("client_id"), body)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) groupOAuthClientSecret(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	secret, err := s.svc.RotateGroupOAuthClientSecret(r.Context(), who, iam.GroupByID(g.ID), r.PathValue("client_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, OAuthClientSecret{ClientSecret: secret})
}

func (s *Service) groupOAuthClientDelete(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	if err := s.svc.DeleteGroupOAuthClient(r.Context(), who, iam.GroupByID(g.ID), r.PathValue("client_id")); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

// handleMeOAuthConsentsGET lists the group clients the caller connected.
func (s *Service) handleMeOAuthConsentsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	consents, err := s.svc.OAuthConsents(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	all(w, consents)
}

// handleMeOAuthConsentDELETE disconnects a group client: the caller
// withdraws consent to it.
func (s *Service) handleMeOAuthConsentDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	who, hasIdentity := verify.IdentityFromContext(r.Context())
	if !ok || !hasIdentity || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	if err := s.svc.WithdrawConsent(r.Context(), who, claims.UserID, r.PathValue("client_id")); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}
