package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

// HandleEmailVerifyConfirmLinkPOST handles POST /auth/email/verify/confirm-link
//
// This accepts a token from a verification link. The value is case-sensitive and must not be normalized.
// Note: verification still supports code-based confirmation; apps can embed the code in the link too.
func HandleEmailVerifyConfirmLinkPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type reqBody struct {
		Token string `json:"token"`
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLEmailVerifyConfirm) {
			ginutil.TooMany(c)
			return
		}
		var req reqBody
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Token) == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		_, err := svc.ConfirmEmailVerification(c.Request.Context(), strings.TrimSpace(req.Token))
		if err != nil {
			ginutil.BadRequest(c, "invalid_or_expired_token")
			return
		}

		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
