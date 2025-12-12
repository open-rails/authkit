package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleUserSessionsDELETE(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLAuthSessionsRevokeAll) {
			ginutil.TooMany(c)
			return
		}
		uid, _ := c.Get("auth.user_id")
		if err := svc.RevokeAllSessions(c.Request.Context(), uid.(string), nil); err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_revoke_all", err, "failed to revoke all sessions")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
