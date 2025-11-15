package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleUserSessionsGET(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLAuthSessionsList) {
			ginutil.TooMany(c)
			return
		}
		uid, _ := c.Get("auth.user_id")
		sessions, err := svc.ListUserSessions(c.Request.Context(), uid.(string))
		if err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_list", err, "failed to list sessions")
			return
		}
		arr := make([]gin.H, 0, len(sessions))
		for _, s := range sessions {
			arr = append(arr, gin.H{"session_id": s.ID, "family_id": s.FamilyID, "created_at": s.CreatedAt, "last_used_at": s.LastUsedAt, "expires_at": s.ExpiresAt, "ip": s.IPAddr, "ua": s.UserAgent})
		}
		c.JSON(http.StatusOK, gin.H{"data": arr})
	}
}
