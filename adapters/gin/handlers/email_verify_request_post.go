package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleEmailVerifyRequestPOST(svc *core.Service, rl ginutil.RateLimiter) gin.HandlerFunc {
	type verifyReq struct {
		Email string `json:"email"`
	}
	return func(c *gin.Context) {
		// Email verification requires email sender
		if !svc.HasEmailSender() {
			ginutil.ServerErrWithLog(c, "email_verification_unavailable", nil, "email sender not configured for verification requests")
			return
		}
		if !ginutil.AllowNamed(c, rl, ginutil.RLEmailVerifyRequest) {
			ginutil.TooMany(c)
			return
		}
		var req verifyReq
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Email) == "" {
			c.JSON(http.StatusOK, gin.H{"ok": true})
			return
		}
		_ = svc.RequestEmailVerification(c.Request.Context(), req.Email, 0)
		c.JSON(http.StatusAccepted, gin.H{"ok": true})
	}
}
