package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleAdminUserToggleActivePOST toggles user ban status.
//
// Note: This endpoint is kept for backward compatibility with older admin UIs.
// The preferred routes are /auth/admin/users/ban and /auth/admin/users/unban.
func HandleAdminUserToggleActivePOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body struct {
			UserID string `json:"user_id"`
			Banned *bool  `json:"banned"`
		}
		if err := c.ShouldBindJSON(&body); err != nil || body.UserID == "" || body.Banned == nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		if *body.Banned {
			if err := svc.BanUser(c.Request.Context(), body.UserID); err != nil {
				ginutil.ServerErrWithLog(c, "failed_to_ban", err, "failed to ban user")
				return
			}
		} else {
			if err := svc.UnbanUser(c.Request.Context(), body.UserID); err != nil {
				ginutil.ServerErrWithLog(c, "failed_to_unban", err, "failed to unban user")
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":      true,
			"user_id": body.UserID,
			"banned":  *body.Banned,
		})
	}
}
