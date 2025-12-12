package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminUsersSetUsernamePOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type setUsernameReq struct {
		UserID   string `json:"user_id"`
		Username string `json:"username"`
	}
	return func(c *gin.Context) {
		var req setUsernameReq
		if err := c.ShouldBindJSON(&req); err != nil || req.UserID == "" || req.Username == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminRolesGrant) {
			ginutil.TooMany(c)
			return
		}
		if err := svc.UpdateUsername(c.Request.Context(), req.UserID, req.Username); err != nil {
			ginutil.BadRequest(c, "failed_to_update_username")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
