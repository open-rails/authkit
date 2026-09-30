package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/siws"
)

// siwsDomain is the domain bound into the SIWS message the wallet signs, the
// protocol's anti-phishing anchor: the frontend BaseURL host, else the issuer
// host. It comes from configuration only, never from a request header.
func siwsDomain(baseURL, issuer string) string {
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
	var req SolanaChallengeRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}

	address := strings.TrimSpace(req.Address)
	if address == "" {
		fail(w, errmodel.CodeAddressRequired)
		return
	}
	if err := siws.ValidateAddress(address); err != nil {
		fail(w, errmodel.CodeInvalidAddress)
		return
	}

	if strings.TrimSpace(req.Username) != "" {
		if err := s.svc.ValidateUsername(req.Username); err != nil {
			writeError(w, err)
			return
		}
	}

	domain := siwsDomain(s.cfg.Frontend.BaseURL, s.cfg.Token.Issuer)
	if domain == "" {
		serverErr(w, "challenge_failed", errors.New("authkit: no SIWS domain: set Frontend.BaseURL or a URL Token.Issuer"))
		return
	}

	input, err := s.svc.GenerateSIWSChallenge(r.Context(), domain, address, req.Username)
	if err != nil {
		serverErr(w, "challenge_failed", err)
		return
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, input.IssuedAt)
	if err != nil {
		serverErr(w, "challenge_failed", err)
		return
	}
	writeJSON(w, http.StatusOK, SolanaChallenge{Nonce: input.Nonce, IssuedAt: issuedAt, Message: siws.ConstructMessage(input)})
}

func (s *Service) handleSolanaLoginPOST(w http.ResponseWriter, r *http.Request) {
	output, ok := decodeSIWSOutput(w, r)
	if !ok {
		return
	}

	out, err := s.svc.VerifySIWSAndLogin(r.Context(), output, nil)
	if err != nil {
		writeError(w, fallback(err, errmodel.CodeAuthenticationFailed))
		return
	}

	if s.writeLoginContinuation(w, r, out, nil) {
		return
	}
	if out.Created {
		go s.svc.SendWelcome(context.Background(), out.UserID)
	}

	writeJSON(w, http.StatusOK, SolanaLoginResult{
		TokenSet: s.deliverRefreshToken(w, r, out.Session.TokenSet()),
		Created:  out.Created,
		User:     SolanaUser{ID: out.UserID, SolanaAddress: output.Account.Address},
	})
}

func (s *Service) handleMeSolanaWalletPUT(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	if !s.requireProvenContact(w, r, claims.UserID) {
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}
	output, ok := decodeSIWSOutput(w, r)
	if !ok {
		return
	}

	if err := s.svc.LinkSolanaWallet(r.Context(), claims.UserID, output); err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, SolanaLink{SolanaAddress: output.Account.Address})
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
	var req SolanaSignInRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return siws.SignInOutput{}, false
	}
	signature, err := decodeSIWSB64(req.Output.Signature)
	if err != nil {
		fail(w, errmodel.CodeInvalidSignatureEncoding)
		return siws.SignInOutput{}, false
	}
	signedMessage, err := decodeSIWSB64(req.Output.SignedMessage)
	if err != nil {
		fail(w, errmodel.CodeInvalidMessageEncoding)
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
