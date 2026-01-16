package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleAdminUsersBanPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type banReq struct {
		UserID string  `json:"user_id"`
		Reason *string `json:"reason"`
		Until  *string `json:"until"`
	}
	return func(c *gin.Context) {
		var req banReq
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.UserID) == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}
		if !ginutil.AllowNamed(c, rl, ginutil.RLAdminUserSessionsRevokeAll) {
			ginutil.TooMany(c)
			return
		}
		bannedBy := strings.TrimSpace(c.GetString("auth.user_id"))
		if bannedBy == "" {
			ginutil.Unauthorized(c, "unauthorized")
			return
		}
		var untilPtr *time.Time
		if req.Until != nil {
			untilStr := strings.TrimSpace(*req.Until)
			if untilStr != "" {
				parsed, err := time.Parse(time.RFC3339, untilStr)
				if err != nil {
					ginutil.BadRequest(c, "invalid_until")
					return
				}
				parsed = parsed.UTC()
				untilPtr = &parsed
			}
		}
		if err := svc.BanUser(c.Request.Context(), req.UserID, req.Reason, untilPtr, bannedBy); err != nil {
			ginutil.ServerErrWithLog(c, "failed_to_ban", err, "failed to ban user")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
