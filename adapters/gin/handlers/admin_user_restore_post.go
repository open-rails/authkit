package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleAdminUserRestorePOST restores a soft-deleted user (clears deleted_at and re-enables the account).
func HandleAdminUserRestorePOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := strings.TrimSpace(c.Param("user_id"))
		if userID == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminUserSessionsRevokeAll) {
			ginutil.TooMany(c)
			return
		}

		if err := svc.RestoreUser(c.Request.Context(), userID); err != nil {
			if errors.Is(err, core.ErrUserNotFound) {
				ginutil.NotFound(c, "not_found")
				return
			}
			ginutil.ServerErrWithLog(c, "failed_to_restore_user", err, "failed to restore user")
			return
		}

		c.JSON(http.StatusOK, gin.H{"ok": true, "user_id": userID})
	}
}
