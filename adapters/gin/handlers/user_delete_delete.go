package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleUserDeleteDELETE(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLUserDelete) {
			ginutil.TooMany(c)
			return
		}
		uid, _ := c.Get("auth.user_id")
		userID, _ := uid.(string)
		_ = svc.SoftDeleteUser(c.Request.Context(), userID)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
