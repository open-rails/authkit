package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandlePendingRegistrationResendPOST(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	type resendReq struct {
		Email string `json:"email"`
	}
	return func(c *gin.Context) {
		// Email verification requires email sender
		if !svc.HasEmailSender() {
			ginutil.ServerErrWithLog(c, "email_unavailable", nil, "email sender not configured for registration resend")
			return
		}

		// Rate limiting - dedicated limit for registration resend
		if !ginutil.AllowNamed(c, rl, ginutil.RLAuthRegisterResendEmail) {
			ginutil.TooMany(c)
			return
		}

		var req resendReq
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Email) == "" {
			c.JSON(http.StatusAccepted, gin.H{"ok": true})
			return
		}

		email := strings.TrimSpace(req.Email)

		// Look up existing pending registration
		pendingUser, err := svc.GetPendingRegistrationByEmail(c.Request.Context(), email)
		if err == nil && pendingUser != nil {
			// Resend by creating new pending registration with same credentials (generates new code)
			_, _ = svc.CreatePendingRegistration(c.Request.Context(), email, pendingUser.Username, pendingUser.PasswordHash, 0)
		}
		// Fail silently for security (prevent email enumeration)

		c.JSON(http.StatusAccepted, gin.H{"ok": true, "message": "If a pending registration exists, a new code has been sent."})
	}
}
