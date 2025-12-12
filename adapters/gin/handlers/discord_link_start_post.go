package handlers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	oidckit "github.com/PaulFidika/authkit/oidc"
	"github.com/gin-gonic/gin"
)

// HandleDiscordLinkStartPOST begins a Discord OAuth2 link flow for the current user.
func HandleDiscordLinkStartPOST(cfg OIDCConfig, svc core.Verifier, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLOIDCStart) {
			ginutil.TooMany(c)
			return
		}
		uidVal, _ := c.Get("auth.user_id")
		userID, _ := uidVal.(string)
		if strings.TrimSpace(userID) == "" {
			ginutil.Unauthorized(c, "unauthorized")
			return
		}

		// Build redirect URI for this request (prefix-aware)
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
		if strings.HasSuffix(path, "/link/start") {
			path = strings.TrimSuffix(path, "/link/start") + "/callback"
		} else {
			path = "/auth/oauth/discord/callback"
		}
		redirectURI := scheme + "://" + host + path

		// Store state with LinkUserID
		st := ginutil.RandB64(24)
		if err := cfg.StateCache.Put(c.Request.Context(), st, oidckit.StateData{Provider: "discord", RedirectURI: redirectURI, LinkUserID: userID}); err != nil {
			ginutil.ServerErrWithLog(c, "state_store_failed", err, "failed to store discord state")
			return
		}

		// Build Discord authorize URL using configured client_id and scopes
		rp, ok := cfg.Manager.Provider("discord")
		if !ok || strings.TrimSpace(rp.ClientID) == "" {
			ginutil.BadRequest(c, "unknown_provider")
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
		c.JSON(http.StatusOK, gin.H{"auth_url": authURL.String(), "state": st})
	}
}
