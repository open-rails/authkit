package handlers

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/PaulFidika/authkit/siws"
	"github.com/gin-gonic/gin"
)

// HandleSolanaLoginPost handles POST /auth/solana/login
// Verifies a SIWS signature and authenticates the user.
func HandleSolanaLoginPost(cfg SIWSConfig, svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	// Request types matching the SIWS output format
	type accountReq struct {
		Address   string `json:"address" binding:"required"`
		PublicKey string `json:"publicKey"` // Optional, base64 encoded
	}
	type outputReq struct {
		Account       accountReq `json:"account" binding:"required"`
		Signature     string     `json:"signature" binding:"required"`     // base64 encoded
		SignedMessage string     `json:"signedMessage" binding:"required"` // base64 encoded
	}
	type loginReq struct {
		Output outputReq `json:"output" binding:"required"`
	}

	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLSolanaLogin) {
			ginutil.TooMany(c)
			return
		}

		var req loginReq
		if err := c.ShouldBindJSON(&req); err != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		// Decode signature from base64
		signature, err := base64.StdEncoding.DecodeString(req.Output.Signature)
		if err != nil {
			// Try URL-safe base64
			signature, err = base64.RawURLEncoding.DecodeString(req.Output.Signature)
			if err != nil {
				ginutil.BadRequest(c, "invalid_signature_encoding")
				return
			}
		}

		// Decode signed message from base64
		signedMessage, err := base64.StdEncoding.DecodeString(req.Output.SignedMessage)
		if err != nil {
			// Try URL-safe base64
			signedMessage, err = base64.RawURLEncoding.DecodeString(req.Output.SignedMessage)
			if err != nil {
				ginutil.BadRequest(c, "invalid_message_encoding")
				return
			}
		}

		// Decode public key if provided
		var publicKey []byte
		if req.Output.Account.PublicKey != "" {
			publicKey, err = base64.StdEncoding.DecodeString(req.Output.Account.PublicKey)
			if err != nil {
				publicKey, _ = base64.RawURLEncoding.DecodeString(req.Output.Account.PublicKey)
			}
		}

		// Build SIWS output
		output := siws.SignInOutput{
			Account: siws.AccountInfo{
				Address:   req.Output.Account.Address,
				PublicKey: publicKey,
			},
			Signature:     signature,
			SignedMessage: signedMessage,
		}

		// Verify and login
		accessToken, expiresAt, refreshToken, userID, created, err := svc.VerifySIWSAndLogin(
			c.Request.Context(),
			cfg.Cache,
			output,
			nil,
		)
		if err != nil {
			// Distinguish between different error types
			errMsg := err.Error()
			switch {
			case contains(errMsg, "challenge not found"):
				ginutil.Unauthorized(c, "challenge_expired")
			case contains(errMsg, "signature verification failed"):
				ginutil.Unauthorized(c, "invalid_signature")
			case contains(errMsg, "address mismatch"):
				ginutil.BadRequest(c, "address_mismatch")
			case contains(errMsg, "timestamp validation failed"):
				ginutil.Unauthorized(c, "challenge_expired")
			default:
				ginutil.Unauthorized(c, "authentication_failed")
			}
			return
		}

		// Get Solana address for response
		solanaAddress := req.Output.Account.Address

		// Send welcome email if new user (fire and forget)
		if created {
			go svc.SendWelcome(c.Request.Context(), userID)
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"expires_in":    int64(time.Until(expiresAt).Seconds()),
			"refresh_token": refreshToken,
			"created":       created,
			"user": gin.H{
				"id":             userID,
				"solana_address": solanaAddress,
			},
		})
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
