package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleUser2FADisablePOST disables 2FA for the current user
func HandleUser2FADisablePOST(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLUserPasswordChange) {
			ginutil.TooMany(c)
			return
		}
		uid := c.GetString("auth.user_id")
		if uid == "" {
			ginutil.Unauthorized(c, "unauthorized")
			return
		}

		err := svc.Disable2FA(c.Request.Context(), uid)
		if err != nil {
			ginutil.ServerErrWithLog(c, "disable_2fa_failed", err, "failed to disable 2fa")
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true})
	}
}
