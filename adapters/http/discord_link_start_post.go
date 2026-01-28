package authhttp

import (
	"net/http"
	"net/url"
	"strings"

	oidckit "github.com/PaulFidika/authkit/oidc"
)

func (s *Service) handleDiscordLinkStartPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLOIDCStart) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}

	scheme := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if host == "" {
		host = r.Host
	}
	path := r.URL.Path
	if strings.HasSuffix(path, "/link/start") {
		path = strings.TrimSuffix(path, "/link/start") + "/callback"
	} else {
		path = "/auth/oauth/discord/callback"
	}
	redirectURI := scheme + "://" + host + path

	st := randB64(24)
	if err := s.stateCache().Put(r.Context(), st, oidckit.StateData{Provider: "discord", RedirectURI: redirectURI, LinkUserID: claims.UserID}); err != nil {
		serverErr(w, "state_store_failed")
		return
	}

	rp, ok := s.oidcManager().Provider("discord")
	if !ok || strings.TrimSpace(rp.ClientID) == "" {
		badRequest(w, "unknown_provider")
		return
	}
	q := url.Values{}
	q.Set("client_id", rp.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	scopes := []string{"identify", "email"}
	if len(rp.Scopes) > 0 {
		scopes = rp.Scopes
	}
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", st)

	authURL := url.URL{Scheme: "https", Host: "discord.com", Path: "/api/oauth2/authorize", RawQuery: q.Encode()}
	writeJSON(w, http.StatusOK, map[string]any{"auth_url": authURL.String(), "state": st})
}
