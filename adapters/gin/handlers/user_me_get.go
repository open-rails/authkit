package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

type userMeResponse struct {
	ID              string   `json:"id"`
	Email           *string  `json:"email"`
	PhoneNumber     *string  `json:"phone_number"`
	Username        string   `json:"username"`
	DiscordUsername *string  `json:"discord_username,omitempty"`
	EmailVerified   bool     `json:"email_verified"`
	PhoneVerified   bool     `json:"phone_verified"`
	HasPassword     bool     `json:"has_password"`
	Roles           []string `json:"roles"`
	Entitlements    []string `json:"entitlements"`
	Biography       *string  `json:"biography,omitempty"`
}

// HandleUserMeGET returns the current user's profile information
func HandleUserMeGET(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
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

		adminUser, err := svc.AdminGetUser(c.Request.Context(), uid)
		if err != nil || adminUser == nil {
			ginutil.ServerErrWithLog(c, "user_lookup_failed", err, "failed to fetch user profile")
			return
		}

		// Get username from DB or fallback to JWT claim
		username := ""
		if adminUser.Username != nil {
			username = strings.TrimSpace(*adminUser.Username)
		}
		if username == "" {
			if raw, ok := c.Get("auth.username"); ok {
				if s, ok2 := raw.(string); ok2 {
					username = strings.TrimSpace(s)
				}
			}
		}
		// Username is required - if still empty, return error
		if username == "" {
			ginutil.ServerErrWithLog(c, "username_missing", nil, "username missing in database and claims")
			return
		}

		hasPassword := svc.HasPassword(c.Request.Context(), adminUser.ID)

		resp := userMeResponse{
			ID:              adminUser.ID,
			Email:           adminUser.Email,
			PhoneNumber:     adminUser.PhoneNumber,
			Username:        username,
			DiscordUsername: adminUser.DiscordUsername,
			EmailVerified:   adminUser.EmailVerified,
			PhoneVerified:   adminUser.PhoneVerified,
			HasPassword:     hasPassword,
			Roles:           adminUser.Roles,
			Entitlements:    adminUser.Entitlements,
			Biography:       adminUser.Biography,
		}

		c.JSON(http.StatusOK, resp)
	}
}
