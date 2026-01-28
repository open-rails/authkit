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
		Code        string `json:"code"` // token from reset link (legacy field name)
		NewPassword string `json:"new_password"`
		Identifier  string `json:"identifier"` // email or phone number (optional; legacy)
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

		// Token is case-sensitive; do NOT normalize.
		code := strings.TrimSpace(req.Code)
		identifier := strings.TrimSpace(req.Identifier)
		var err error

		// If identifier is provided, determine if it's phone or email
		if identifier != "" {
			phoneRegex := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
			isPhone := phoneRegex.MatchString(identifier)

			if isPhone {
				_, err = svc.ConfirmPhonePasswordReset(c.Request.Context(), identifier, code, req.NewPassword)
			} else {
				_, err = svc.ConfirmPasswordReset(c.Request.Context(), code, req.NewPassword)
			}
		} else {
			_, err = svc.ConfirmPasswordReset(c.Request.Context(), code, req.NewPassword)
		}

		if err != nil {
			ginutil.BadRequest(c, "invalid_or_expired_token")
			return
		}

		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
