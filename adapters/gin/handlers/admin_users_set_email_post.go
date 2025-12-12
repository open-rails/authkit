package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminUsersSetEmailPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type setEmailReq struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
	}
	return func(c *gin.Context) {
		var req setEmailReq
		if err := c.ShouldBindJSON(&req); err != nil || req.UserID == "" || req.Email == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminRolesGrant) {
			ginutil.TooMany(c)
			return
		}
		if err := svc.UpdateEmail(c.Request.Context(), req.UserID, req.Email); err != nil {
			ginutil.BadRequest(c, "failed_to_update_email")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
