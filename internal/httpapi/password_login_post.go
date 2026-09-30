package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

// handlePasswordLoginPOST: decode, rate-limit, one engine call, one switch.
// The login policy (identifier resolution, pending-registration recovery, the
// verification gate, credentials, the account gate, 2FA, session) is
// authkit.PasswordLogin (ak#318).
func (s *Service) handlePasswordLoginPOST(w http.ResponseWriter, r *http.Request) {
	var req PasswordLoginRequest
	if err := decodeJSON(r, &req); err != nil || req.Password == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	// Passwords are high-entropy secrets: the route's per-IP bucket is the only
	// limit, so no stranger can lock an account out.
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
	s.writeAuthResult(w, r, out, authExtras{})
}
