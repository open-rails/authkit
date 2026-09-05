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
		Identifier: identifier, Password: req.Password, UserAgent: r.UserAgent(), IP: remoteIP(r),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	switch out.Kind {
	case embedded.LoginSessionIssued:
		s.writeTokenSet(w, r, http.StatusOK, out.Session.TokenSet())
	case embedded.LoginVerificationRequired:
		writeVerificationRequired(w, out.Verification.Identifier, out.Verification.Channel)
	case embedded.LoginTwoFactorRequired:
		s.writeTwoFactorRequired(w, out.UserID, out.Challenge)
	case embedded.LoginTwoFAEnrollmentRequired:
		s.send2FAEnrollmentRequired(w, r, out.UserID)
	default:
		unauthorized(w, loginRejectionCode(out.Reason))
	}
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

// writeTwoFactorRequired emits the 403 2fa_required envelope: the issued
// challenge, the factor the code went to, and the factor menu.
func (s *Service) writeTwoFactorRequired(w http.ResponseWriter, userID string, ch *embedded.TwoFactorChallenge) {
	sendErrData(w, http.StatusForbidden, authkit.CodeTwoFARequired, map[string]any{
		"user_id":         userID,
		"method":          ch.Method,
		"verification_id": embedded.MaskDestination(ch.Destination),
		"challenge":       ch.Challenge,
		"default_factor": twoFactorFactorResponse{
			ID:          ch.Factor.ID,
			Method:      ch.Factor.Method,
			IsDefault:   ch.Factor.IsDefault,
			PhoneNumber: ch.Factor.PhoneNumber,
		},
		"available_factors": twoFactorFactorResponses(ch.Factors),
	})
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
