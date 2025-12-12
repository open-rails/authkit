package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminRolesGrantPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type roleReq struct{ UserID, Role string }
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminRolesGrant) {
			ginutil.TooMany(c)
			return
		}
		var req roleReq
		if err := c.ShouldBindJSON(&req); err != nil || req.UserID == "" || req.Role == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		if svc == nil {
			ginutil.SendErr(c, http.StatusServiceUnavailable, "roles_unavailable")
			return
		}
		if err := svc.AssignRoleBySlug(c.Request.Context(), req.UserID, req.Role); err != nil {
			ginutil.ServerErrWithLog(c, "assign_failed", err, "failed to grant role")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
