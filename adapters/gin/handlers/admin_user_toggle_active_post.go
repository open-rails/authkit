package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleAdminUserToggleActivePOST toggles the is_active property of a user record.
func HandleAdminUserToggleActivePOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body struct {
			UserID   string `json:"user_id"`
			IsActive *bool  `json:"is_active"`
		}
		if err := c.ShouldBindJSON(&body); err != nil || body.UserID == "" || body.IsActive == nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		err := svc.SetUserActive(c.Request.Context(), body.UserID, *body.IsActive)
		if err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_toggle_active", err, "Failed to toggle is_active")
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":        true,
			"user_id":   body.UserID,
			"is_active": *body.IsActive,
		})
	}
}
