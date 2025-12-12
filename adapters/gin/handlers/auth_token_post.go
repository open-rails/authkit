package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAuthTokenPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLAuthToken) {
			ginutil.TooMany(c)
			return
		}
		var body struct {
			GrantType    string `json:"grant_type"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.ShouldBindJSON(&body); err != nil || !strings.EqualFold(body.GrantType, "refresh_token") || strings.TrimSpace(body.RefreshToken) == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		ua := c.Request.UserAgent()
		ip := ginutil.ParseIP(c.ClientIP())
		accessToken, exp, newRT, err := svc.ExchangeRefreshToken(c.Request.Context(), body.RefreshToken, ua, ip)
		if err != nil {
			ginutil.Unauthorized(c, "invalid_refresh_token")
			return
		}
		c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "expires_in": int(time.Until(exp).Seconds()), "refresh_token": newRT})
	}
}
