package handlers

import (
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	pwhash "github.com/PaulFidika/authkit/password"
	"github.com/gin-gonic/gin"
)

// HandleUserPasswordPOST allows an authenticated user to set or change their password.
// If the user already has a password, current_password is required and must verify.
// Always enforces the shared password validator and revokes other sessions on success.
func HandleUserPasswordPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type reqBody struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLUserPasswordChange) {
			ginutil.TooMany(c)
			return
		}
		uid, _ := c.Get("auth.user_id")
		userID, _ := uid.(string)
		if userID == "" {
			ginutil.Unauthorized(c, "not_authenticated")
			return
		}
		var body reqBody
		if err := c.ShouldBindJSON(&body); err != nil || pwhash.Validate(body.NewPassword) != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		// If a password exists, require current_password
		hadPwd := svc.HasPassword(c.Request.Context(), userID)
		if hadPwd && body.CurrentPassword == "" {
			ginutil.BadRequest(c, "current_password_required")
			return
		}
		// Keep current session (sid) after change
		var keep *string
		if sidv, ok := c.Get("auth.sid"); ok {
			if sid, ok2 := sidv.(string); ok2 && sid != "" {
				keep = &sid
			}
		}
		if err := svc.ChangePassword(c.Request.Context(), userID, body.CurrentPassword, body.NewPassword, keep); err != nil {
			ginutil.BadRequest(c, "password_change_failed")
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
