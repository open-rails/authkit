package handlers

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandlePasswordResetRequestPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type resetReq struct {
		Identifier string `json:"identifier"` // Email or phone number (E.164 format)
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLPasswordResetRequest) {
			ginutil.TooMany(c)
			return
		}

		var req resetReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusAccepted, gin.H{"ok": true})
			return
		}

		identifier := strings.TrimSpace(req.Identifier)
		if identifier == "" {
			c.JSON(http.StatusAccepted, gin.H{"ok": true})
			return
		}

		// Detect if identifier is phone or email
		phoneRegex := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
		isPhone := phoneRegex.MatchString(identifier)

		if isPhone {
			// Phone password reset
			if !svc.HasSMSSender() {
				ginutil.ServerErrWithLog(c, "sms_unavailable", nil, "sms sender not configured for password reset")
				return
			}
			_ = svc.RequestPhonePasswordReset(c.Request.Context(), identifier, 0)
			} else {
				// Email password reset
				if !svc.HasEmailSender() {
					ginutil.ServerErrWithLog(c, "email_password_reset_unavailable", nil, "email sender not configured for password reset")
					return
				}
				_ = svc.RequestPasswordReset(c.Request.Context(), identifier, 0)
			}

		c.JSON(http.StatusAccepted, gin.H{"ok": true, "message": "If this email or phone number is registered, password reset instructions will be sent."})
	}
}
