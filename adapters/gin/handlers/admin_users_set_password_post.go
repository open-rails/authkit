package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	pwhash "github.com/PaulFidika/authkit/password"
	"github.com/gin-gonic/gin"
)

// HandleAdminUsersSetPasswordPOST allows an admin to force-set a user's password.
func HandleAdminUsersSetPasswordPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {

	type setPasswordReq struct {
		UserID   string `json:"user_id"`
		Password string `json:"password"`
	}
	return func(c *gin.Context) {
		var req setPasswordReq
		if err := c.ShouldBindJSON(&req); err != nil || req.UserID == "" || req.Password == "" || pwhash.Validate(req.Password) != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminRolesGrant) {
			ginutil.TooMany(c)
			return
		}
		if err := svc.AdminSetPassword(c.Request.Context(), req.UserID, req.Password); err != nil {
			ginutil.BadRequest(c, "failed_to_set_password")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
