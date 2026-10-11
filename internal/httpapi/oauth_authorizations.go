package httpapi

// The API the SPA answers a pending OAuth sign-in request through (#430):
// the authorize endpoint sends the browser to Frontend.AuthorizePath with
// the request's id; the SPA reads it, signs the user in as usual (second
// factors and step-up included), then approves it for that sign-in or
// declines it.

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

func (s *Service) handleOAuthAuthorizationGET(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("authorization_id"))
	a, err := s.svc.OAuthAuthorization(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	client, _ := config.FindOAuthClient(s.cfg.AuthorizationServer, a.ClientID)
	out := OAuthAuthorizationRequest{
		ID: id, ClientID: a.ClientID, ClientName: client.Name, Scopes: a.Scopes,
		Prompt: a.Prompt, MaxAgeSeconds: a.MaxAge, ExpiresAt: a.ExpiresAt,
		Agreements: []iam.Agreement{},
	}
	for _, key := range client.Agreements {
		for _, d := range s.cfg.Agreements {
			if d.Key == key {
				out.Agreements = append(out.Agreements, iam.Agreement{Key: d.Key, Version: d.Version, URL: d.URL})
			}
		}
	}
	if out.ClientName == "" {
		out.ClientName = a.ClientID
	}
	if out.Scopes == nil {
		out.Scopes = []string{}
	}
	if out.Prompt == nil {
		out.Prompt = []string{}
	}
	if a.Resource != "" {
		out.Resource = &a.Resource
	}
	if a.LoginHint != "" {
		out.LoginHint = &a.LoginHint
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handleOAuthAuthorizationApprovePOST(w http.ResponseWriter, r *http.Request) {
	claims, _ := verify.ClaimsFromContext(r.Context())
	if !claims.IsUser() || claims.SessionID == "" {
		// Only a user's own session may approve: a device key stands on no
		// session the code could carry.
		fail(w, errmodel.CodeForbidden)
		return
	}
	target, err := s.svc.ApproveOAuthAuthorization(r.Context(), claims.UserID, claims.SessionID, r.PathValue("authorization_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, OAuthAuthorizationResult{RedirectTo: target})
}

func (s *Service) handleOAuthAuthorizationDeclinePOST(w http.ResponseWriter, r *http.Request) {
	var req OAuthAuthorizationDeclineRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	target, err := s.svc.DeclineOAuthAuthorization(r.Context(), r.PathValue("authorization_id"), req.Error)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, OAuthAuthorizationResult{RedirectTo: target})
}
