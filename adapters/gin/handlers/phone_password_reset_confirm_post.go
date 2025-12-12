package handlers

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	pwhash "github.com/PaulFidika/authkit/password"
	"github.com/gin-gonic/gin"
)

// HandlePhonePasswordResetConfirmPOST handles POST /auth/phone/password/reset/confirm
func HandlePhonePasswordResetConfirmPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type confirmReq struct {
		PhoneNumber string `json:"phone_number"`
		Code        string `json:"code"`
		NewPassword string `json:"new_password"`
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLPasswordResetConfirm) {
			ginutil.TooMany(c)
			return
		}

		var req confirmReq
		if err := c.ShouldBindJSON(&req); err != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		phone := strings.TrimSpace(req.PhoneNumber)
		// Normalize code to uppercase (codes are case-insensitive alphanumeric)
		code := strings.ToUpper(strings.TrimSpace(req.Code))
		newPass := req.NewPassword

		// Validate phone format
		phoneRegex := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
		if !phoneRegex.MatchString(phone) {
			ginutil.BadRequest(c, "invalid_phone_number")
			return
		}

		// Validate code format (6 alphanumeric characters)
		if len(code) != 6 {
			ginutil.BadRequest(c, "invalid_code")
			return
		}

		// Validate password
		if err := pwhash.Validate(newPass); err != nil {
			ginutil.BadRequest(c, "weak_password")
			return
		}

		// Verify code and reset password
		userID, err := svc.ConfirmPhonePasswordReset(c.Request.Context(), phone, code, newPass)
		if err != nil {
			ginutil.BadRequest(c, "invalid_or_expired_code")
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":      true,
			"user_id": userID,
			"message": "Password reset successfully. You can now log in with your new password.",
		})
	}
}
