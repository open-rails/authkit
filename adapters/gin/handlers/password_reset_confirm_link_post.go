package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	pwhash "github.com/PaulFidika/authkit/password"
	"github.com/gin-gonic/gin"
)

// HandlePasswordResetConfirmLinkPOST handles POST /auth/password/reset/confirm-link
//
// This is the link-first variant. The token is case-sensitive and must not be normalized.
func HandlePasswordResetConfirmLinkPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type resetConfirmReq struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLPasswordResetConfirm) {
			ginutil.TooMany(c)
			return
		}
		var req resetConfirmReq
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Token) == "" || req.NewPassword == "" || pwhash.Validate(req.NewPassword) != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		_, err := svc.ConfirmPasswordReset(c.Request.Context(), strings.TrimSpace(req.Token), req.NewPassword)
		if err != nil {
			ginutil.BadRequest(c, "invalid_or_expired_token")
			return
		}

		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
