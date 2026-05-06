package authhttp

import (
	"net/http"
	"strings"

	oidckit "github.com/open-rails/authkit/oidc"
)

func (s *Service) oidcManager() *oidckit.Manager {
	providers := s.oidcProviders
	if providers == nil {
		providers = map[string]oidckit.RPConfig{}
	}
	return oidckit.NewManagerFromMinimal(providers)
}

func (s *Service) handleOIDCLinkStartPOST(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if strings.EqualFold(strings.TrimSpace(provider), "discord") {
		s.handleDiscordLinkStartPOST(w, r)
		return
	}
	if !s.allow(r, RLOIDCStart) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
		return
	}
	state := randB64(32)
	nonce := randB64(16)
	verifier, challenge, err := oidckit.GeneratePKCE()
	if err != nil {
		serverErr(w, "pkce_generation_failed")
		return
	}
	redirectURI := buildRedirectURI(r, provider)
	url, err := s.oidcManager().Begin(r.Context(), provider, state, nonce, challenge, redirectURI)
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
