package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminUserSessionsGET(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminUserSessionsList) {
			ginutil.TooMany(c)
			return
		}
		userID := c.Param("user_id")
		sessions, err := svc.AdminListUserSessions(c.Request.Context(), userID)
		if err != nil {
			ginutil.ServerErrWithLog(c, "list_failed", err, "failed to list user sessions")
			return
		}
		out := make([]gin.H, 0, len(sessions))
		for _, s := range sessions {
			out = append(out, gin.H{"session_id": s.ID, "family_id": s.FamilyID, "created_at": s.CreatedAt, "last_used_at": s.LastUsedAt, "expires_at": s.ExpiresAt, "revoked_at": s.RevokedAt, "ua": s.UserAgent, "ip": s.IPAddr})
		}
		c.JSON(http.StatusOK, gin.H{"data": out})
	}
}
