package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleLogoutDELETE handles DELETE /auth/logout without importing parent package types.
// It relies on standard context keys set by Auth middleware: "auth.user_id" and "authkit.claims".
func HandleLogoutDELETE(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLAuthLogout) {
			ginutil.TooMany(c)
			return
		}
		uidVal, ok := c.Get("auth.user_id")
		if !ok {
			ginutil.Unauthorized(c, "unauthorized")
			return
		}
		userID, _ := uidVal.(string)
		// Extract sid from context (set by middleware from JWT)
		sid := c.GetString("auth.sid")
		if strings.TrimSpace(sid) == "" {
			ginutil.BadRequest(c, "missing_sid_claim")
			return
		}
		if err := svc.RevokeSessionByIDForUser(c.Request.Context(), userID, sid); err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_logout", err, "failed to revoke session during logout")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
