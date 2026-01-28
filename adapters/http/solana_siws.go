package authhttp

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	core "github.com/PaulFidika/authkit/core"
	"github.com/PaulFidika/authkit/siws"
)

func (s *Service) handleSolanaChallengePOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLSolanaChallenge) {
		tooMany(w)
		return
	}

	var req struct {
		Address  string `json:"address"`
		Username string `json:"username"`
		ChainID  string `json:"chain_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}

	address := strings.TrimSpace(req.Address)
	if address == "" {
		badRequest(w, "address_required")
		return
	}
	if err := siws.ValidateAddress(address); err != nil {
		badRequest(w, "invalid_address")
		return
	}

	domain := s.solanaDomain
	if domain == "" {
		origin := r.Header.Get("Origin")
		if origin != "" {
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
		domain = r.Host
		if idx := strings.Index(domain, ":"); idx > 0 {
			domain = domain[:idx]
		}
	}

	input, err := s.svc.GenerateSIWSChallenge(r.Context(), s.siwsCache(), domain, address, req.Username)
	if err != nil {
		serverErr(w, "challenge_failed")
		return
	}
	writeJSON(w, http.StatusOK, input)
}

func (s *Service) handleSolanaLoginPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLSolanaLogin) {
		tooMany(w)
		return
	}

	var req struct {
		Output struct {
			Account struct {
				Address   string `json:"address"`
				PublicKey string `json:"publicKey"`
			} `json:"account"`
			Signature     string `json:"signature"`
			SignedMessage string `json:"signedMessage"`
		} `json:"output"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}

	signature, err := base64.StdEncoding.DecodeString(req.Output.Signature)
	if err != nil {
		signature, err = base64.RawURLEncoding.DecodeString(req.Output.Signature)
		if err != nil {
			badRequest(w, "invalid_signature_encoding")
			return
		}
	}
	signedMessage, err := base64.StdEncoding.DecodeString(req.Output.SignedMessage)
	if err != nil {
		signedMessage, err = base64.RawURLEncoding.DecodeString(req.Output.SignedMessage)
		if err != nil {
			badRequest(w, "invalid_message_encoding")
			return
		}
	}

	var publicKey []byte
	if req.Output.Account.PublicKey != "" {
		publicKey, err = base64.StdEncoding.DecodeString(req.Output.Account.PublicKey)
		if err != nil {
			publicKey, _ = base64.RawURLEncoding.DecodeString(req.Output.Account.PublicKey)
		}
	}

	output := siws.SignInOutput{
		Account: siws.AccountInfo{
			Address:   req.Output.Account.Address,
			PublicKey: publicKey,
		},
		Signature:     signature,
		SignedMessage: signedMessage,
	}

	accessToken, expiresAt, refreshToken, userID, created, err := s.svc.VerifySIWSAndLogin(r.Context(), s.siwsCache(), output, nil)
	if err != nil {
		if errors.Is(err, core.ErrUserBanned) {
			unauthorized(w, "user_banned")
			return
		}
		errMsg := err.Error()
		switch {
		case contains(errMsg, "challenge not found"):
			unauthorized(w, "challenge_expired")
		case contains(errMsg, "signature verification failed"):
			unauthorized(w, "invalid_signature")
		case contains(errMsg, "address mismatch"):
			badRequest(w, "address_mismatch")
		case contains(errMsg, "timestamp validation failed"):
			unauthorized(w, "challenge_expired")
		default:
			unauthorized(w, "authentication_failed")
		}
		return
	}

	if created {
		go s.svc.SendWelcome(context.Background(), userID)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int64(time.Until(expiresAt).Seconds()),
		"refresh_token": refreshToken,
		"created":       created,
		"user": map[string]any{
			"id":             userID,
			"solana_address": req.Output.Account.Address,
		},
	})
}

func (s *Service) handleSolanaLinkPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLSolanaLink) {
		tooMany(w)
		return
	}

	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "authentication_required")
		return
	}

	var req struct {
		Output struct {
			Account struct {
				Address   string `json:"address"`
				PublicKey string `json:"publicKey"`
			} `json:"account"`
			Signature     string `json:"signature"`
			SignedMessage string `json:"signedMessage"`
		} `json:"output"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "invalid_request")
		return
	}

	signature, err := base64.StdEncoding.DecodeString(req.Output.Signature)
	if err != nil {
		signature, err = base64.RawURLEncoding.DecodeString(req.Output.Signature)
		if err != nil {
			badRequest(w, "invalid_signature_encoding")
			return
		}
	}
	signedMessage, err := base64.StdEncoding.DecodeString(req.Output.SignedMessage)
	if err != nil {
		signedMessage, err = base64.RawURLEncoding.DecodeString(req.Output.SignedMessage)
		if err != nil {
			badRequest(w, "invalid_message_encoding")
			return
		}
	}

	var publicKey []byte
	if req.Output.Account.PublicKey != "" {
		publicKey, err = base64.StdEncoding.DecodeString(req.Output.Account.PublicKey)
		if err != nil {
			publicKey, _ = base64.RawURLEncoding.DecodeString(req.Output.Account.PublicKey)
		}
	}

	output := siws.SignInOutput{
		Account: siws.AccountInfo{
			Address:   req.Output.Account.Address,
			PublicKey: publicKey,
		},
		Signature:     signature,
		SignedMessage: signedMessage,
	}

	if err := s.svc.LinkSolanaWallet(r.Context(), s.siwsCache(), claims.UserID, output); err != nil {
		errMsg := err.Error()
		switch {
		case contains(errMsg, "challenge not found"):
			unauthorized(w, "challenge_expired")
		case contains(errMsg, "signature verification failed"):
			unauthorized(w, "invalid_signature")
		case contains(errMsg, "wallet already linked"):
			sendErr(w, http.StatusConflict, "wallet_already_linked")
		default:
			serverErr(w, "link_failed")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":        true,
		"message":        "Solana wallet linked successfully",
		"solana_address": req.Output.Account.Address,
	})
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
