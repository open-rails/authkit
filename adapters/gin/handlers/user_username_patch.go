package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleUserUsernamePATCH(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLUserUpdateUsername) {
			ginutil.TooMany(c)
			return
		}
		uid, _ := c.Get("auth.user_id")
		userID, _ := uid.(string)
		var body struct {
			Username string `json:"username"`
		}
		if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Username) == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		if err := ginutil.ValidateUsername(body.Username); err != nil {
			ginutil.BadRequest(c, err.Error())
			return
		}

		if err := svc.UpdateUsername(c.Request.Context(), userID, body.Username); err != nil {
			ginutil.BadRequest(c, "failed_to_update_username")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
