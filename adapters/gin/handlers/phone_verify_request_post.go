package handlers

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// E.164 phone number regex
var phoneVerifyRegex = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

// HandlePhoneVerifyRequestPOST handles POST /auth/phone/verify/request
// Sends a verification code to an existing user's phone number.
func HandlePhoneVerifyRequestPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type verifyReq struct {
		PhoneNumber string `json:"phone_number"`
	}
	return func(c *gin.Context) {
		// Phone verification requires SMS sender
		if !svc.HasSMSSender() {
			ginutil.ServerErrWithLog(c, "phone_verification_unavailable", nil, "sms sender not configured for verification requests")
			return
		}
		if !ginutil.AllowNamed(c, rl, ginutil.RLPhoneVerifyRequest) {
			ginutil.TooMany(c)
			return
		}
		var req verifyReq
		if err := c.ShouldBindJSON(&req); err != nil {
			// Fail silently to prevent phone enumeration
			c.JSON(http.StatusAccepted, gin.H{"ok": true})
			return
		}

		phone := strings.TrimSpace(req.PhoneNumber)
		if phone == "" || !phoneVerifyRegex.MatchString(phone) {
			// Fail silently to prevent phone enumeration
			c.JSON(http.StatusAccepted, gin.H{"ok": true})
			return
		}

		// Request verification (looks up user internally and sends SMS)
		_ = svc.RequestPhoneVerification(c.Request.Context(), phone, 0)
		c.JSON(http.StatusAccepted, gin.H{"ok": true})
	}
}
