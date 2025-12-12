package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminUsersUnbanPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type userIDReq struct {
		UserID string `json:"user_id"`
	}
	return func(c *gin.Context) {
		var req userIDReq
		if err := c.ShouldBindJSON(&req); err != nil || req.UserID == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminUserSessionsRevokeAll) {
			ginutil.TooMany(c)
			return
		}
		if err := svc.SetActive(c.Request.Context(), req.UserID, true); err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_unban", err, "failed to unban user")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
