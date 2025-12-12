package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminUserSessionsDELETE(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminUserSessionsRevokeAll) {
			ginutil.TooMany(c)
			return
		}
		userID := c.Param("user_id")
		if userID == "" {
			ginutil.BadRequest(c, "missing_user_id")
			return
		}
		if err := svc.AdminRevokeUserSessions(c.Request.Context(), userID); err != nil {
			ginutil.ServerErrWithLog(c, "revoke_failed", err, "failed to revoke user sessions")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
