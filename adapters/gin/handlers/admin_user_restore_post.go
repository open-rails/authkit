package handlers

import (
	"net/http"

	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleAdminUserRestorePOST restores a soft-deleted user (clears deleted_at and re-enables the account).
func HandleAdminUserRestorePOST(svc core.Provider) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.Param("user_id")
		if userID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
			return
		}

		if err := svc.RestoreUser(c.Request.Context(), userID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_restore_user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
