package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleUserEmailChangeRequestPOST initiates an email change request.
// Requires the user to be authenticated and provide their current password for security.
func HandleUserEmailChangeRequestPOST(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	type reqBody struct {
		NewEmail string `json:"new_email"`
		Password string `json:"password"`
	}
	return func(c *gin.Context) {
		// Email verification requires email sender
		if !svc.HasEmailSender() {
			ginutil.ServerErrWithLog(c, "email_verification_unavailable", nil, "email sender not configured for email change request")
			return
		}

		if !ginutil.AllowNamed(c, rl, ginutil.RLUserEmailChangeRequest) {
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
		if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.NewEmail) == "" || body.Password == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		// Verify current password
		_, _, err := svc.PasswordLoginByUserID(c.Request.Context(), userID, body.Password, nil)
		if err != nil {
			ginutil.Unauthorized(c, "invalid_password")
			return
		}

		// Request email change
		if err := svc.RequestEmailChange(c.Request.Context(), userID, body.NewEmail); err != nil {
			// Don't leak specific error details for security
			if strings.Contains(err.Error(), "same as current") {
				ginutil.BadRequest(c, "email_unchanged")
			} else if strings.Contains(err.Error(), "already in use") {
				ginutil.BadRequest(c, "email_in_use")
			} else {
				ginutil.BadRequest(c, "failed_to_request_email_change")
			}
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"ok":      true,
			"message": "Verification code sent to new email address",
		})
	}
}
