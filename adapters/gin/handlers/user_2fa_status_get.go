package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

type twoFactorStatusResponse struct {
	Enabled     bool    `json:"enabled"`
	Method      string  `json:"method"` // "email" or "sms"
	PhoneNumber *string `json:"phone_number,omitempty"`
}

// HandleUser2FAStatusGET returns the current user's 2FA settings
func HandleUser2FAStatusGET(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLUserMe) {
			ginutil.TooMany(c)
			return
		}
		uid := c.GetString("auth.user_id")
		if uid == "" {
			ginutil.Unauthorized(c, "unauthorized")
			return
		}

		settings, err := svc.Get2FASettings(c.Request.Context(), uid)
		if err != nil {
			// No 2FA configured
			c.JSON(http.StatusOK, twoFactorStatusResponse{
				Enabled: false,
				Method:  "email",
			})
			return
		}

		resp := twoFactorStatusResponse{
			Enabled:     settings.Enabled,
			Method:      settings.Method,
			PhoneNumber: settings.PhoneNumber,
		}

		c.JSON(http.StatusOK, resp)
	}
}
