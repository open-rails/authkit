package authhttp

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/open-rails/authkit/verify"
	"net/http"
	"net/url"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/siws"
)

// siwsDomainFromConfig derives the SIWS message domain (bare host, no scheme or
// port) from AuthKit config — the frontend BaseURL host if set, else the issuer
// host. Returns "" when neither yields a host, leaving the request-based fallback
// (Origin header, then r.Host) to supply the domain.
func siwsDomainFromConfig(baseURL, issuer string) string {
	for _, raw := range []string{baseURL, issuer} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	return ""
}

func (s *Service) handleSolanaChallengePOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLSolanaChallenge) {
		return
	}

	var req struct {
		Address  string `json:"address"`
		Username string `json:"username"`
		ChainID  string `json:"chain_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}

	address := strings.TrimSpace(req.Address)
	if address == "" {
		badRequest(w, ErrAddressRequired)
		return
	}
	if err := siws.ValidateAddress(address); err != nil {
		badRequest(w, ErrInvalidAddress)
		return
	}

	// #143: the SIWS domain is derived from config (frontend BaseURL host, else
	// issuer host), with request-based fallback. There is no WithSolanaDomain option.
	cfg := s.svc.Config()
	domain := siwsDomainFromConfig(cfg.Frontend.BaseURL, cfg.Token.Issuer)
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
		serverErr(w, ErrChallengeFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nonce":     input.Nonce,
		"issued_at": input.IssuedAt,
		"message":   siws.ConstructMessage(input),
	})
}

func (s *Service) handleSolanaLoginPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLSolanaLogin) {
		return
	}

	output, ok := decodeSIWSOutput(w, r)
	if !ok {
		return
	}

	accessToken, expiresAt, refreshToken, userID, created, err := s.svc.VerifySIWSAndLogin(r.Context(), s.siwsCache(), output, nil)
	if err != nil {
		if errors.Is(err, authkit.ErrUserBanned) {
			unauthorized(w, ErrUserBanned)
			return
		}
		if errors.Is(err, authkit.ErrRegistrationDisabled) {
			registrationDisabled(w)
			return
		}
		switch {
		case errors.Is(err, authkit.ErrSIWSChallengeNotFound), errors.Is(err, authkit.ErrSIWSChallengeExpired):
			unauthorized(w, ErrChallengeExpired)
		case errors.Is(err, authkit.ErrSIWSSignatureInvalid):
			unauthorized(w, ErrInvalidSignature)
		case errors.Is(err, authkit.ErrSIWSAddressMismatch):
			badRequest(w, ErrAddressMismatch)
		case errors.Is(err, authkit.ErrSIWSDomainInvalid):
			unauthorized(w, ErrAuthenticationFailed)
		case errors.Is(err, authkit.ErrSIWSTimestampInvalid):
			unauthorized(w, ErrChallengeExpired)
		default:
			unauthorized(w, ErrAuthenticationFailed)
		}
		return
	}

	if created {
		go s.svc.SendWelcome(context.Background(), userID)
	}

	writeAccessTokenJSON(w, http.StatusOK, newAuthTokens(accessToken, refreshToken, expiresAt), map[string]any{
		"created": created,
		"user": map[string]any{
			"id":             userID,
			"solana_address": output.Account.Address,
		},
	})
}

func (s *Service) handleSolanaLinkPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLSolanaLink) {
		return
	}

	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrAuthenticationRequired)
		return
	}

	output, ok := decodeSIWSOutput(w, r)
	if !ok {
		return
	}

	if err := s.svc.LinkSolanaWallet(r.Context(), s.siwsCache(), claims.UserID, output); err != nil {
		switch {
		case errors.Is(err, authkit.ErrSIWSChallengeNotFound), errors.Is(err, authkit.ErrSIWSChallengeExpired):
			unauthorized(w, ErrChallengeExpired)
		case errors.Is(err, authkit.ErrSIWSSignatureInvalid):
			unauthorized(w, ErrInvalidSignature)
		case errors.Is(err, authkit.ErrSIWSAddressMismatch):
			badRequest(w, ErrAddressMismatch)
		case errors.Is(err, authkit.ErrSIWSDomainInvalid):
			unauthorized(w, ErrAuthenticationFailed)
		case errors.Is(err, authkit.ErrWalletAlreadyLinked):
			sendErr(w, http.StatusConflict, ErrWalletAlreadyLinked)
		default:
			serverErr(w, ErrLinkFailed)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":        true,
		"message":        "Solana wallet linked successfully",
		"solana_address": output.Account.Address,
	})
}

// decodeSIWSB64 decodes a base64 string, trying StdEncoding then RawURLEncoding —
// wallets vary in which they emit for the signature/message/public-key fields.
func decodeSIWSB64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// decodeSIWSOutput decodes the shared `{output:{account,signature,signedMessage}}`
// SIWS request body used by both the login and link handlers. On a decode failure
// it writes the appropriate 400 and returns ok=false (the caller just returns).
func decodeSIWSOutput(w http.ResponseWriter, r *http.Request) (siws.SignInOutput, bool) {
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
		badRequest(w, ErrInvalidRequest)
		return siws.SignInOutput{}, false
	}
	signature, err := decodeSIWSB64(req.Output.Signature)
	if err != nil {
		badRequest(w, ErrInvalidSignatureEncoding)
		return siws.SignInOutput{}, false
	}
	signedMessage, err := decodeSIWSB64(req.Output.SignedMessage)
	if err != nil {
		badRequest(w, ErrInvalidMessageEncoding)
		return siws.SignInOutput{}, false
	}
	// Public key is optional and best-effort (the address is authoritative).
	var publicKey []byte
	if req.Output.Account.PublicKey != "" {
		publicKey, _ = decodeSIWSB64(req.Output.Account.PublicKey)
	}
	return siws.SignInOutput{
		Account:       siws.AccountInfo{Address: req.Output.Account.Address, PublicKey: publicKey},
		Signature:     signature,
		SignedMessage: signedMessage,
	}, true
}
