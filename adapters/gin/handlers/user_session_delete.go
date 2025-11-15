package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleUserSessionDELETE(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLAuthSessionsRevoke) {
			ginutil.TooMany(c)
			return
		}
		uid, _ := c.Get("auth.user_id")
		sid := c.Param("id")
		if strings.TrimSpace(sid) == "" {
			ginutil.BadRequest(c, "missing_session_id")
			return
		}
		if err := svc.RevokeSessionByIDForUser(c.Request.Context(), uid.(string), sid); err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_revoke", err, "failed to revoke session")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
