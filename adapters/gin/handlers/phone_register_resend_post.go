package handlers

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandlePhoneRegisterResendPOST handles POST /auth/register/resend-phone
func HandlePhoneRegisterResendPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type resendReq struct {
		PhoneNumber string `json:"phone_number"`
	}
	// E.164 phone regex
	var phoneRegex = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

	return func(c *gin.Context) {
		// Phone resend requires SMS sender
		if !svc.HasSMSSender() {
			ginutil.ServerErrWithLog(c, "phone_unavailable", nil, "sms sender not configured for phone registration resend")
			return
		}

		if !ginutil.AllowNamed(c, rl, ginutil.RLAuthRegisterResendPhone) {
			ginutil.TooMany(c)
			return
		}

		var req resendReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusAccepted, gin.H{"ok": true})
			return
		}

		phone := strings.TrimSpace(req.PhoneNumber)
		if phone == "" || !phoneRegex.MatchString(phone) {
			// Accept to avoid phone enumeration
			c.JSON(http.StatusAccepted, gin.H{"ok": true})
			return
		}

		// Look up existing pending phone registration
		pending, err := svc.GetPendingPhoneRegistrationByPhone(c.Request.Context(), phone)
		if err == nil && pending != nil {
			// Recreate pending to generate a new code and send SMS
			_, _ = svc.CreatePendingPhoneRegistration(c.Request.Context(), phone, pending.Username, pending.PasswordHash)
		}
		// Fail silently for security

		c.JSON(http.StatusAccepted, gin.H{"ok": true, "message": "If a pending registration exists, a new code has been sent."})
	}
}
