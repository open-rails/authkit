package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	oidckit "github.com/PaulFidika/authkit/oidc"
	"github.com/gin-gonic/gin"
)

func HandleOIDCLinkStartPOST(cfg OIDCConfig, svc core.Verifier, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLOIDCStart) {
			ginutil.TooMany(c)
			return
		}
		provider := c.Param("provider")
		uidVal, _ := c.Get("auth.user_id")
		userID, _ := uidVal.(string)
		if userID == "" {
			ginutil.Unauthorized(c, "unauthorized")
			return
		}
		state := ginutil.RandB64(32)
		nonce := ginutil.RandB64(16)
		verifier, challenge, err := oidckit.GeneratePKCE()
		if err != nil {
			ginutil.ServerErrWithLog(c, "pkce_generation_failed", err, "failed to generate pkce verifier for oidc link")
			return
		}
		redirectURI := ginutil.BuildRedirectURI(c, provider)
		url, err := cfg.Manager.Begin(c.Request.Context(), provider, state, nonce, challenge, redirectURI)
		if err != nil {
			ginutil.BadRequest(c, "oidc_begin_failed")
			return
		}
		if err := cfg.StateCache.Put(c.Request.Context(), state, oidckit.StateData{Provider: provider, Verifier: verifier, Nonce: nonce, RedirectURI: redirectURI, LinkUserID: userID}); err != nil {
			ginutil.ServerErrWithLog(c, "state_store_failed", err, "failed to store oidc link state")
			return
		}
		c.JSON(http.StatusOK, gin.H{"auth_url": url, "state": state})
	}
}
