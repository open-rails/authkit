package authhttp

import (
	"github.com/open-rails/authkit/verify"
	"net/http"
	"sync"

	"github.com/open-rails/authkit/oidckit"
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
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
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
			serverErr(w, ErrPKCEGenerationFailed)
			return
		}
	}
	redirectURI := s.buildRedirectURI(r, provider)
	// AK F3: bind state to this browser (login/link CSRF defense).
	s.setStateCookie(w, r, state)
	url, err := manager.Begin(r.Context(), provider, state, nonce, challenge, redirectURI)
	if err != nil {
		badRequest(w, ErrOIDCBeginFailed)
		return
	}
	if err := s.stateCache().Put(r.Context(), state, oidckit.StateData{Provider: provider, Verifier: verifier, Nonce: nonce, RedirectURI: redirectURI, LinkUserID: claims.UserID}); err != nil {
		serverErr(w, ErrStateStoreFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"auth_url": url, "state": state})
}
