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
		s.fail(w, errmodel.CodeInvalidRequest)
		return
	}
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		s.fail(w, errmodel.CodeInvalidRequest)
		return
	}
	// Spent before any lookup, so an identifier with no account is refused
	// alike; given back only once an account's own password proves right.
	refund, refused := s.spendByIdentifier(w, r, RLPasswordLoginIdentifier, identifier)
	if refused {
		return
	}

	out, err := s.svc.PasswordLogin(r.Context(), authflow.PasswordLoginInput{
		Identifier: identifier, Password: req.Password, UserAgent: r.UserAgent(), IP: s.requestIP(r),
	})
	if err != nil {
		s.writeError(w, err)
		return
	}
	// A pending sign-up's password names no account, wherever it matched.
	if out.Kind != authflow.LoginRejected && out.UserID != "" {
		refund()
	}
	s.writeAuthResult(w, r, out, authExtras{})
}
