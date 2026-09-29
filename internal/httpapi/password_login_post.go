package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

// handlePasswordLoginPOST: decode, rate-limit, one engine call, one switch.
// The login policy (identifier resolution, pending-registration recovery, the
// verification gate, credentials, liveness, 2FA, session) is
// authkit.PasswordLogin (ak#318).
func (s *Service) handlePasswordLoginPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier string `json:"identifier"` // email, phone number, or username
		Password   string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Password == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	// Passwords are high-entropy secrets: the route's per-IP bucket is the only
	// limit, so no stranger can lock an account out (docs/security/rate-limits.md).
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}

	out, err := s.svc.PasswordLogin(r.Context(), authflow.PasswordLoginInput{
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

func loginRejectionCode(reason error) errmodel.Code {
	switch {
	case errors.Is(reason, errmodel.ErrUserBanned):
		return errmodel.CodeUserBanned
	case errors.Is(reason, errmodel.ErrPasswordResetRequired):
		return errmodel.CodePasswordResetRequired
	default:
		return errmodel.CodeInvalidCredentials
	}
}

// writeVerificationRequired emits the 403 verification_required envelope
// (#313), parallel to 2fa_required. By the time this is called the engine has
// already (re)sent a fresh verification code; the frontend routes the user to
// the OTP verify page using metadata.identifier + metadata.channel.
func writeVerificationRequired(w http.ResponseWriter, identifier, channel string) {
	fail(w, errmodel.CodeVerificationRequired, errmodel.WithMetadata(map[string]any{
		"identifier": identifier,
		"channel":    channel,
	}))
}
