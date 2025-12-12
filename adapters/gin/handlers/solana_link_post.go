package handlers

import (
	"encoding/base64"
	"net/http"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/PaulFidika/authkit/siws"
	"github.com/gin-gonic/gin"
)

// HandleSolanaLinkPost handles POST /auth/solana/link
// Links a Solana wallet to an existing authenticated user account.
func HandleSolanaLinkPost(cfg SIWSConfig, svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
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
	type linkReq struct {
		Output outputReq `json:"output" binding:"required"`
	}

	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLSolanaLink) {
			ginutil.TooMany(c)
			return
		}

		// Get authenticated user from context
		userID, exists := c.Get("user_id")
		if !exists {
			ginutil.Unauthorized(c, "authentication_required")
			return
		}
		userIDStr, ok := userID.(string)
		if !ok || userIDStr == "" {
			ginutil.Unauthorized(c, "authentication_required")
			return
		}

		var req linkReq
		if err := c.ShouldBindJSON(&req); err != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		// Decode signature from base64
		signature, err := base64.StdEncoding.DecodeString(req.Output.Signature)
		if err != nil {
			signature, err = base64.RawURLEncoding.DecodeString(req.Output.Signature)
			if err != nil {
				ginutil.BadRequest(c, "invalid_signature_encoding")
				return
			}
		}

		// Decode signed message from base64
		signedMessage, err := base64.StdEncoding.DecodeString(req.Output.SignedMessage)
		if err != nil {
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

		// Link wallet to user
		err = svc.LinkSolanaWallet(c.Request.Context(), cfg.Cache, userIDStr, output)
		if err != nil {
			errMsg := err.Error()
			switch {
			case contains(errMsg, "challenge not found"):
				ginutil.Unauthorized(c, "challenge_expired")
			case contains(errMsg, "signature verification failed"):
				ginutil.Unauthorized(c, "invalid_signature")
			case contains(errMsg, "wallet already linked"):
				c.JSON(http.StatusConflict, gin.H{"error": "wallet_already_linked"})
			default:
				ginutil.ServerErrWithLog(c, "link_failed", err, "failed to link Solana wallet")
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success":        true,
			"message":        "Solana wallet linked successfully",
			"solana_address": req.Output.Account.Address,
		})
	}
}
