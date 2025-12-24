package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleUserPhoneChangeRequestPOST initiates a phone number change request.
// Requires the user to be authenticated and provide their current password for security.
func HandleUserPhoneChangeRequestPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type reqBody struct {
		NewPhone string `json:"new_phone"`
		Password string `json:"password"`
	}
	return func(c *gin.Context) {
		if !svc.HasSMSSender() {
			ginutil.ServerErrWithLog(c, "phone_verification_unavailable", nil, "SMS sender not configured for phone change request")
			return
		}

		if !ginutil.AllowNamed(c, rl, ginutil.RLUserPhoneChangeRequest) {
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
		if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.NewPhone) == "" || body.Password == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		// Verify current password
		_, _, err := svc.PasswordLoginByUserID(c.Request.Context(), userID, body.Password, nil)
		if err != nil {
			ginutil.Unauthorized(c, "invalid_password")
			return
		}

		// Request phone change
		if err := svc.RequestPhoneChange(c.Request.Context(), userID, body.NewPhone); err != nil {
			if strings.Contains(err.Error(), "same as current") {
				ginutil.BadRequest(c, "phone_unchanged")
			} else if strings.Contains(err.Error(), "already in use") {
				ginutil.BadRequest(c, "phone_in_use")
			} else {
				ginutil.BadRequest(c, "failed_to_request_phone_change")
			}
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"ok":      true,
			"message": "Verification code sent to new phone",
		})
	}
}
