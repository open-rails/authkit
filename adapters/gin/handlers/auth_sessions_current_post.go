package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAuthSessionsCurrentPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLAuthSessionsCurrent) {
			ginutil.TooMany(c)
			return
		}
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.RefreshToken) == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		sid, err := svc.ResolveSessionByRefresh(c.Request.Context(), body.RefreshToken)
		if err != nil || sid == "" {
			ginutil.Unauthorized(c, "invalid_refresh_token")
			return
		}
		c.JSON(http.StatusOK, gin.H{"session_id": sid})
	}
}
