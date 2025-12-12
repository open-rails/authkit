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

func HandlePasswordResetConfirmPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type resetConfirmReq struct {
		Code        string `json:"code"`
		NewPassword string `json:"new_password"`
		Identifier  string `json:"identifier"` // email or phone number (required for phone resets)
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLPasswordResetConfirm) {
			ginutil.TooMany(c)
			return
		}
		var req resetConfirmReq
		if err := c.ShouldBindJSON(&req); err != nil || req.Code == "" || req.NewPassword == "" || pwhash.Validate(req.NewPassword) != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		// Normalize code to uppercase (codes are case-insensitive)
		code := strings.ToUpper(strings.TrimSpace(req.Code))
		identifier := strings.TrimSpace(req.Identifier)

		var userID string
		var err error

		// If identifier is provided, determine if it's phone or email
		if identifier != "" {
			phoneRegex := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
			isPhone := phoneRegex.MatchString(identifier)

			if isPhone {
				userID, err = svc.ConfirmPhonePasswordReset(c.Request.Context(), identifier, code, req.NewPassword)
			} else {
				userID, err = svc.ConfirmPasswordReset(c.Request.Context(), code, req.NewPassword)
			}
		} else {
			userID, err = svc.ConfirmPasswordReset(c.Request.Context(), code, req.NewPassword)
		}

		if err != nil {
			ginutil.BadRequest(c, "invalid_or_expired_code")
			return
		}

		// Audit with IP/UA at the edge
		ua := c.Request.UserAgent()
		ip := c.ClientIP()
		uaPtr, ipPtr := &ua, &ip
		svc.LogLogin(c.Request.Context(), userID, "password_reset_confirm", "", ipPtr, uaPtr)

		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
