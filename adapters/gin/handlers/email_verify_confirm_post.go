package handlers

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/gin-gonic/gin"
)

func HandleEmailVerifyConfirmPOST(svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type verifyConfirmReq struct {
		Code string `json:"code"`
	}
	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLEmailVerifyConfirm) {
			ginutil.TooMany(c)
			return
		}
		var req verifyConfirmReq
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Code) == "" {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		// Normalize code to uppercase (codes are case-insensitive)
		code := strings.ToUpper(strings.TrimSpace(req.Code))

		var userID string
		var err error

		// Try pending registration first (new flow)
		userID, err = svc.ConfirmPendingRegistration(c.Request.Context(), code)
		if err == nil && userID != "" {
			// Success - pending registration confirmed and user created
			// Issue tokens and return them
			if err := IssueTokensForUser(c, svc, userID, "email_verification"); err != nil {
				ginutil.ServerErrWithLog(c, "token_issue_failed", err, "failed to issue tokens after registration")
				return
			}
			return
		}

		// Fall back to existing email verification (for OAuth users or email changes)
		userID, err = svc.ConfirmEmailVerification(c.Request.Context(), code)
		if err != nil {
			ginutil.BadRequest(c, "invalid_or_expired_code")
			return
		}

		// Issue tokens and return them
		if err := IssueTokensForUser(c, svc, userID, "email_verification"); err != nil {
			ginutil.ServerErrWithLog(c, "token_issue_failed", err, "failed to issue tokens after verification")
			return
		}
	}
}

// IssueTokensForUser issues access and refresh tokens for a user and returns them in the response.
func IssueTokensForUser(c *gin.Context, svc core.Provider, userID string, method string) error {
	// Issue refresh session
	ua := c.Request.UserAgent()
	ip := net.ParseIP(c.ClientIP())
	sid, rt, _, err := svc.IssueRefreshSession(c.Request.Context(), userID, ua, ip)
	if err != nil {
		return err
	}

	// Log the login event
	ipStr := c.ClientIP()
	uaPtr, ipPtr := &ua, &ipStr
	svc.LogLogin(c.Request.Context(), userID, method, sid, ipPtr, uaPtr)

	// Issue access token (email will be fetched internally by IssueAccessToken if empty)
	claims := map[string]any{"sid": sid}
	accessToken, exp, err := svc.IssueAccessToken(c.Request.Context(), userID, "", claims)
	if err != nil {
		return err
	}

	// Return token response matching login endpoint format
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int64(time.Until(exp).Seconds()),
		"refresh_token": rt,
	})
	return nil
}
