package handlers

import (
	"net/url"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	oidckit "github.com/PaulFidika/authkit/oidc"
	"github.com/gin-gonic/gin"
)

// HandleDiscordLoginGET starts the Discord OAuth2 authorization code flow (non-OIDC).
func HandleDiscordLoginGET(cfg OIDCConfig, svc core.Verifier, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLOIDCStart) {
			ginutil.TooMany(c)
			return
		}
		provider := "discord"
		// Build redirect URI to /auth/oauth/discord/callback, preserving any router prefix
		scheme := c.Request.Header.Get("X-Forwarded-Proto")
		host := c.Request.Header.Get("X-Forwarded-Host")
		if scheme == "" {
			if c.Request.TLS != nil {
				scheme = "https"
			} else {
				scheme = "http"
			}
		}
		if host == "" {
			host = c.Request.Host
		}
		path := c.Request.URL.Path
		if strings.HasSuffix(path, "/login") {
			path = strings.TrimSuffix(path, "/login") + "/callback"
		} else {
			path = "/auth/oauth/discord/callback"
		}
		redirectURI := scheme + "://" + host + path
			// Persist minimal state for callback validation
			st := ginutil.RandB64(24)
			ui := c.Query("ui")
			if ui != "" && ui != "popup" {
				ginutil.BadRequest(c, "invalid_ui")
				return
			}
			popupNonce := c.Query("popup_nonce")
			if err := cfg.StateCache.Put(c.Request.Context(), st, oidckit.StateData{Provider: provider, RedirectURI: redirectURI, UI: ui, PopupNonce: popupNonce}); err != nil {
				ginutil.ServerErrWithLog(c, "state_store_failed", err, "failed to store oauth state")
				return
			}

		// Build Discord authorize URL
		// Docs: https://discord.com/developers/docs/topics/oauth2#authorization-code-grant
		q := url.Values{}
		// The RPConfig lives in cfg.Manager; we only need client_id
		rp, ok := cfg.Manager.Provider(provider)
		if !ok || strings.TrimSpace(rp.ClientID) == "" {
			ginutil.BadRequest(c, "unknown_provider")
			return
		}
		q.Set("client_id", rp.ClientID)
		q.Set("response_type", "code")
		q.Set("redirect_uri", redirectURI)
		// Minimal scopes for identity and email
		scopes := []string{"identify", "email"}
		if len(rp.Scopes) > 0 {
			scopes = rp.Scopes
		}
		q.Set("scope", strings.Join(scopes, " "))
		q.Set("state", st)

		authorize := url.URL{Scheme: "https", Host: "discord.com", Path: "/api/oauth2/authorize", RawQuery: q.Encode()}
		c.Redirect(302, authorize.String())
	}
}
