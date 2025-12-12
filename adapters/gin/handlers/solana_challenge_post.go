package handlers

import (
	"net/http"
	"strings"

	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	"github.com/PaulFidika/authkit/siws"
	"github.com/gin-gonic/gin"
)

// SIWSConfig holds the SIWS-related dependencies.
type SIWSConfig struct {
	Cache  siws.ChallengeCache
	Domain string // The domain to use in SIWS messages (e.g., "myapp.com")
}

// HandleSolanaChallengePost handles POST /auth/solana/challenge
// Creates a new SIWS challenge for the given wallet address.
func HandleSolanaChallengePost(cfg SIWSConfig, svc core.Provider, rl ginutil.RateLimiter) gin.HandlerFunc {
	type challengeReq struct {
		Address  string `json:"address" binding:"required"`
		Username string `json:"username"` // Optional desired username for new accounts
		ChainID  string `json:"chain_id"` // Optional, defaults to "mainnet"
	}

	return func(c *gin.Context) {
		if !ginutil.AllowNamed(c, rl, ginutil.RLSolanaChallenge) {
			ginutil.TooMany(c)
			return
		}

		var req challengeReq
		if err := c.ShouldBindJSON(&req); err != nil {
			ginutil.BadRequest(c, "invalid_request")
			return
		}

		address := strings.TrimSpace(req.Address)
		if address == "" {
			ginutil.BadRequest(c, "address_required")
			return
		}

		// Validate address format
		if err := siws.ValidateAddress(address); err != nil {
			ginutil.BadRequest(c, "invalid_address")
			return
		}

		// Determine domain from config or request origin
		domain := cfg.Domain
		if domain == "" {
			// Try to get from request origin
			origin := c.GetHeader("Origin")
			if origin != "" {
				// Extract hostname from origin (e.g., "https://myapp.com" -> "myapp.com")
				origin = strings.TrimPrefix(origin, "https://")
				origin = strings.TrimPrefix(origin, "http://")
				if idx := strings.Index(origin, "/"); idx > 0 {
					origin = origin[:idx]
				}
				if idx := strings.Index(origin, ":"); idx > 0 {
					origin = origin[:idx]
				}
				domain = origin
			}
		}
		if domain == "" {
			domain = c.Request.Host
			if idx := strings.Index(domain, ":"); idx > 0 {
				domain = domain[:idx]
			}
		}

		// Generate challenge
		input, err := svc.GenerateSIWSChallenge(c.Request.Context(), cfg.Cache, domain, address, req.Username)
		if err != nil {
			ginutil.ServerErrWithLog(c, "challenge_failed", err, "failed to generate SIWS challenge")
			return
		}

		// Return the challenge input
		c.JSON(http.StatusOK, input)
	}
}
