package handlers

import (
	"log"
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleUserPhoneChangeResendPOST resends the verification code for a pending phone number change.
func HandleUserPhoneChangeResendPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLUserPhoneChangeResend) {
			ginutil.TooMany(c)
			return
		}

		uid, _ := c.Get("auth.user_id")
		userID, _ := uid.(string)
		if userID == "" {
			ginutil.Unauthorized(c, "not_authenticated")
			return
		}

		var body struct {
			Phone string `json:"phone_number"`
		}
		if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Phone) == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		phone := strings.TrimSpace(body.Phone)

		if err := svc.ResendPhoneChangeCode(c.Request.Context(), userID, phone); err != nil {
			log.Println("Error resending phone change code:", err)
			ginutil.BadRequest(c, "no_pending_phone_change")
			return
		}

		c.JSON(http.StatusAccepted, gin.H{
			"ok":      true,
			"message": "Verification code resent",
		})
	}
}
