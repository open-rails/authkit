package authhttp

import (
	"errors"
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

// handlePasswordLoginPOST: decode, rate-limit, one engine call, one switch.
// The login policy (identifier resolution, pending-registration recovery, the
// verification gate, credentials, liveness, 2FA, session) is
// embedded.PasswordLogin (ak#318).
func (s *Service) handlePasswordLoginPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier string `json:"identifier"` // email, phone number, or username
		Password   string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Password == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	// Per-identifier check: prevents distributed brute-force against a single
	// account from many IPs, each spending their own per-IP budget.
	if s.rateLimitedByIdentifier(w, r, RLPasswordLogin, identifier) {
		return
	}
	if identifier == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}

	out, err := s.svc.PasswordLogin(r.Context(), embedded.PasswordLoginInput{
		Identifier: identifier, Password: req.Password, UserAgent: r.UserAgent(), IP: s.requestIP(r),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	if s.writeLoginContinuation(w, r, out, nil) {
		return
	}
	s.writeTokenSet(w, r, http.StatusOK, out.Session.TokenSet())
}

func loginRejectionCode(reason error) authkit.Code {
	switch {
	case errors.Is(reason, authkit.ErrUserBanned):
		return authkit.CodeUserBanned
	case errors.Is(reason, authkit.ErrPasswordResetRequired):
		return authkit.CodePasswordResetRequired
	default:
		return authkit.CodeInvalidCredentials
	}
}

// writeVerificationRequired emits the 403 verification_required envelope
// (#313), parallel to 2fa_required. By the time this is called the engine has
// already (re)sent a fresh verification code; the frontend routes the user to
// the OTP verify page using metadata.identifier + metadata.channel.
func writeVerificationRequired(w http.ResponseWriter, identifier, channel string) {
	sendErrData(w, http.StatusForbidden, authkit.CodeVerificationRequired, map[string]any{
		"identifier": identifier,
		"channel":    channel,
	})
}
