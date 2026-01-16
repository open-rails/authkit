package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminUserDeleteDELETE(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("user_id")
		if id == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminUserSessionsRevokeAll) {
			ginutil.TooMany(c)
			return
		}
		if err := svc.SoftDeleteUser(c.Request.Context(), id); err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_delete", err, "failed to delete user")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
