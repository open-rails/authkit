package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

type enable2FARequest struct {
	Method      string  `json:"method"`       // "email" or "sms"
	PhoneNumber *string `json:"phone_number"` // Required if method="sms"
}

type enable2FAResponse struct {
	Enabled     bool     `json:"enabled"`
	Method      string   `json:"method"`
	BackupCodes []string `json:"backup_codes"` // Show ONCE - user must save these
}

// HandleUser2FAEnablePOST enables 2FA for the current user
func HandleUser2FAEnablePOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
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

		var req enable2FARequest
		if err := c.ShouldBindJSON(&req); err != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		// Validate method
		method := strings.ToLower(strings.TrimSpace(req.Method))
		if method != "email" && method != "sms" {
			ginutil.BadRequest(c, "invalid_method")
			return
		}

		// Validate phone number if method is SMS
		if method == "sms" {
			if req.PhoneNumber == nil || strings.TrimSpace(*req.PhoneNumber) == "" {
				ginutil.BadRequest(c, "phone_number_required")
				return
			}
			// Ensure it's in E.164 format (starts with +)
			phoneNum := strings.TrimSpace(*req.PhoneNumber)
			if !strings.HasPrefix(phoneNum, "+") {
				ginutil.BadRequest(c, "phone_number_must_be_e164")
				return
			}
		}

		// Enable 2FA and generate backup codes
		backupCodes, err := svc.Enable2FA(c.Request.Context(), uid, method, req.PhoneNumber)
		if err != nil {
			ginutil.ServerErrWithLog(c, "enable_2fa_failed", err, "failed to enable 2fa for user")
			return
		}

		c.JSON(http.StatusOK, enable2FAResponse{
			Enabled:     true,
			Method:      method,
			BackupCodes: backupCodes,
		})
	}
}
