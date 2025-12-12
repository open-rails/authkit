package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminUserSessionDELETE(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminUserSessionsRevoke) {
			ginutil.TooMany(c)
			return
		}
		sid := c.Param("session_id")
		if sid == "" {
			ginutil.BadRequest(c, "missing_session_id")
			return
		}
		if err := svc.RevokeSessionByID(c.Request.Context(), sid); err != nil {
			ginutil.ServerErrWithLog(c, "revoke_failed", err, "failed to revoke session")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
