package handlers

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandlePhonePasswordResetRequestPOST handles POST /auth/phone/password/reset/request
func HandlePhonePasswordResetRequestPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type resetReq struct {
		PhoneNumber string `json:"phone_number"`
	}
	return func(c *gin.Context) {
		// Phone password reset requires SMS sender
		if !svc.HasSMSSender() {
			ginutil.ServerErrWithLog(c, "sms_unavailable", nil, "sms sender not configured for phone password reset")
			return
		}

		if !ginutil.AllowNamed(c, rl, ginutil.RLPasswordResetRequest) {
			ginutil.TooMany(c)
			return
		}

		var req resetReq
		if err := c.ShouldBindJSON(&req); err != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		phone := strings.TrimSpace(req.PhoneNumber)

		// Validate E.164 phone format
		phoneRegex := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
		if !phoneRegex.MatchString(phone) {
			ginutil.BadRequest(c, "invalid_phone_number")
			return
		}

		// Always return 202 to prevent user enumeration
		_ = svc.RequestPhonePasswordReset(c.Request.Context(), phone, 0)

		c.JSON(http.StatusAccepted, gin.H{
			"ok":      true,
			"message": "If this phone number is registered, a verification code will be sent via SMS.",
		})
	}
}
