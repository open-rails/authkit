package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleUserEmailChangeResendPOST resends the verification code for a pending email change.
func HandleUserEmailChangeResendPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Email verification requires email sender
		if !svc.HasEmailSender() {
			ginutil.ServerErrWithLog(c, "email_verification_unavailable", nil, "email sender not configured for email change resend")
			return
		}

		if !ginutil.AllowNamed(c, rl, ginutil.RLUserEmailChangeResend) {
			ginutil.TooMany(c)
			return
		}

		uid, _ := c.Get("auth.user_id")
		userID, _ := uid.(string)
		if userID == "" {
			ginutil.Unauthorized(c, "not_authenticated")
			return
		}

		// Resend code
		if err := svc.ResendEmailChangeCode(c.Request.Context(), userID); err != nil {
			ginutil.BadRequest(c, "no_pending_email_change")
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"ok":      true,
			"message": "Verification code resent",
		})
	}
}
