package handlers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	oidckit "github.com/PaulFidika/authkit/oidc"
	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
)

type OIDCConfig struct {
	Manager    *oidckit.Manager
	StateCache oidckit.StateCache
}

func HandleOIDCLoginGET(cfg OIDCConfig, svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLOIDCStart) {
			ginutil.TooMany(c)
			return
		}
		provider := c.Param("provider")
		state := ginutil.RandB64(32)
		nonce := ginutil.RandB64(16) // Generate nonce for ALL providers (security best practice)
		verifier, challenge, err := oidckit.GeneratePKCE()
		if err != nil {
			ginutil.ServerErrWithLog(c, "pkce_generation_failed", err, "failed to generate pkce")
			return
		}
		redirectURI := ginutil.BuildRedirectURI(c, provider)
		authURL, err := cfg.Manager.Begin(c.Request.Context(), provider, state, nonce, challenge, redirectURI)
		if err != nil {
			ginutil.BadRequest(c, "oidc_begin_failed")
			return
		}
		linkUserID := ""
		if c.Query("link") == "1" || strings.EqualFold(c.Query("link"), "true") {
			tokenStr := ginutil.BearerToken(c.GetHeader("Authorization"))
			if tokenStr == "" {
				ginutil.Unauthorized(c, "auth_required_for_link")
				return
			}
			claims := jwt.MapClaims{}
			tok, err := jwt.ParseWithClaims(tokenStr, claims, svc.Keyfunc())
			if err != nil || !tok.Valid {
				ginutil.Unauthorized(c, "invalid_token")
				return
			}
			if sub, _ := claims["sub"].(string); sub != "" {
				linkUserID = sub
			} else {
				ginutil.Unauthorized(c, "invalid_token")
				return
			}
		}
		ui := c.Query("ui")
		popupNonce := c.Query("popup_nonce")
		// Capture origin from Referer for secure postMessage (before OAuth redirect overwrites it)
		origin := "*"
		if referer := c.Request.Referer(); referer != "" {
			if u, err := url.Parse(referer); err == nil && u.Scheme != "" && u.Host != "" {
				origin = u.Scheme + "://" + u.Host
			}
		}
		if err := cfg.StateCache.Put(c.Request.Context(), state, oidckit.StateData{Provider: provider, Verifier: verifier, Nonce: nonce, RedirectURI: redirectURI, LinkUserID: linkUserID, UI: ui, PopupNonce: popupNonce, Origin: origin}); err != nil {
			ginutil.ServerErrWithLog(c, "state_store_failed", err, "failed to store oidc state")
			return
		}
		c.Redirect(http.StatusFound, authURL)
	}
}

// bearer token helper lives in ginutil.BearerToken
