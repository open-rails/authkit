package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleUserUnlinkProviderDELETE(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLUserUnlinkProvider) {
			ginutil.TooMany(c)
			return
		}
		uid, _ := c.Get("auth.user_id")
		userID, _ := uid.(string)
		provider := strings.ToLower(strings.TrimSpace(c.Param("provider")))
		if provider == "" {
			ginutil.BadRequest(c, "invalid_provider")
			return
		}
		hasPwd, links := svc.HasPassword(c.Request.Context(), userID), svc.CountProviderLinks(c.Request.Context(), userID)
		if !hasPwd && links <= 1 {
			ginutil.BadRequest(c, "cannot_unlink_last_login_method")
			return
		}
		if err := svc.UnlinkProvider(c.Request.Context(), userID, provider); err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_unlink", err, "failed to unlink provider")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
