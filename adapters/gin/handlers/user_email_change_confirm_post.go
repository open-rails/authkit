package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleUserEmailChangeConfirmPOST confirms an email change using the verification code.
func HandleUserEmailChangeConfirmPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type reqBody struct {
		Code string `json:"code"`
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLUserEmailChangeConfirm) {
			ginutil.TooMany(c)
			return
		}

		uid, _ := c.Get("auth.user_id")
		userID, _ := uid.(string)
		if userID == "" {
			ginutil.Unauthorized(c, "not_authenticated")
			return
		}

		var body reqBody
		if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Code) == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		// Normalize code to uppercase (codes are case-insensitive)
		code := strings.ToUpper(strings.TrimSpace(body.Code))

		// Confirm email change
		if err := svc.ConfirmEmailChange(c.Request.Context(), userID, code); err != nil {
			ginutil.BadRequest(c, "invalid_or_expired_code")
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":      true,
			"message": "Email changed successfully",
		})
	}
}
