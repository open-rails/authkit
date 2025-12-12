package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

type regenerateCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

// HandleUser2FARegenerateCodesPOST regenerates backup codes for the current user
func HandleUser2FARegenerateCodesPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLUserPasswordChange) {
			ginutil.TooMany(c)
			return
		}
		uid := c.GetString("auth.user_id")
		if uid == "" {
			ginutil.Unauthorized(c, "unauthorized")
			return
		}

		backupCodes, err := svc.RegenerateBackupCodes(c.Request.Context(), uid)
		if err != nil {
			ginutil.ServerErrWithLog(c, "regenerate_codes_failed", err, "failed to regenerate backup codes")
			return
		}

		c.JSON(http.StatusOK, regenerateCodesResponse{
			BackupCodes: backupCodes,
		})
	}
}
