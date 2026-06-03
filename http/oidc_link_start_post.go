package authhttp

import (
	"net/http"
	"sync"

	oidckit "github.com/open-rails/authkit/oidc"
)

func (s *Service) oidcManager() *oidckit.Manager {
	s.oidcMgrOnce.Do(func() {
		s.oidcMgr = oidckit.NewManagerFromProviders(s.authProviders())
	})
	return s.oidcMgr
}

// resetOIDCManagerForTest clears the lazy OIDC manager (http tests that mutate providers after New).
func (s *Service) resetOIDCManagerForTest() {
	s.oidcMgrOnce = sync.Once{}
	s.oidcMgr = nil
}

func (s *Service) handleOIDCLinkStartPOST(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if cfg, ok := s.oauth2Provider(provider); ok {
		s.handleOAuthLinkStartPOST(w, r, cfg.Name)
		return
	}
	if s.rateLimited(w, r, RLOIDCStart) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
		return
	}
	state := randB64(32)
	nonce := randB64(16)
	verifier := ""
	challenge := ""
	manager := s.oidcManager()
	if pc, ok := manager.Provider(provider); ok && pc.PKCE {
		var err error
		verifier, challenge, err = oidckit.GeneratePKCE()
		if err != nil {
			serverErr(w, "pkce_generation_failed")
			return
		}
	}
	redirectURI := buildRedirectURI(r, provider)
	url, err := manager.Begin(r.Context(), provider, state, nonce, challenge, redirectURI)
	if err != nil {
		badRequest(w, "oidc_begin_failed")
		return
	}
	if err := s.stateCache().Put(r.Context(), state, oidckit.StateData{Provider: provider, Verifier: verifier, Nonce: nonce, RedirectURI: redirectURI, LinkUserID: claims.UserID}); err != nil {
		serverErr(w, "state_store_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"auth_url": url, "state": state})
}
