package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

type verify2FARequest struct {
	UserID     string `json:"user_id"`
	Code       string `json:"code"`
	BackupCode bool   `json:"backup_code"` // True if using backup code instead of 2FA code
}

type verify2FAResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// HandleUser2FAVerifyPOST verifies a 2FA code during login and issues tokens
func HandleUser2FAVerifyPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLPasswordLogin) {
			ginutil.TooMany(c)
			return
		}

		var req verify2FARequest
		if err := c.ShouldBindJSON(&req); err != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		userID := strings.TrimSpace(req.UserID)
		code := strings.TrimSpace(req.Code)

		if userID == "" || code == "" {
			ginutil.BadRequest(c, "missing_fields")
			return
		}

		// Verify the code (either 2FA code or backup code)
		var valid bool
		var err error

		if req.BackupCode {
			valid, err = svc.VerifyBackupCode(c.Request.Context(), userID, code)
		} else {
			valid, err = svc.Verify2FACode(c.Request.Context(), userID, code)
		}

		if err != nil || !valid {
			ginutil.Unauthorized(c, "invalid_code")
			return
		}

		// Code verified - issue tokens and create session
		sid, rt, _, err := svc.IssueRefreshSession(c.Request.Context(), userID, c.Request.UserAgent(), nil)
		if err != nil {
			ginutil.ServerErrWithLog(c, "session_creation_failed", err, "failed to create session during 2fa login")
			return
		}

		ua := c.Request.UserAgent()
		ip := c.ClientIP()
		uaPtr, ipPtr := &ua, &ip
		svc.LogLogin(c.Request.Context(), userID, "password_login_2fa", sid, ipPtr, uaPtr)

		// Get user email for token
		usr, _ := svc.AdminGetUser(c.Request.Context(), userID)
		emailForToken := ""
		if usr != nil && usr.Email != nil {
			emailForToken = *usr.Email
		}

		token, exp, err := svc.IssueAccessToken(c.Request.Context(), userID, emailForToken, map[string]any{"sid": sid})
		if err != nil {
			ginutil.ServerErrWithLog(c, "token_creation_failed", err, "failed to issue access token during 2fa login")
			return
		}

		c.JSON(http.StatusOK, verify2FAResponse{
			AccessToken:  token,
			TokenType:    "Bearer",
			ExpiresIn:    int64(time.Until(exp).Seconds()),
			RefreshToken: rt,
		})
	}
}
