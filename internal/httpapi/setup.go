package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

// handleSetupPOST spends a setup link's token on the owner account, then
// signs it in by its new password as /password/login does: the owner role
// makes that sign-in enroll a second factor before any session exists.
func (s *Service) handleSetupPOST(w http.ResponseWriter, r *http.Request) {
	var req SetupRequest
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Token) == "" {
		s.fail(w, errmodel.CodeInvalidRequest)
		return
	}
	owner, err := s.svc.CompleteSetup(r.Context(), req.Token, iam.NewUser{Email: req.Email, Username: req.Username, Password: req.Password})
	if err != nil {
		s.writeError(w, err)
		return
	}
	out, err := s.svc.PasswordLogin(r.Context(), authflow.PasswordLoginInput{
		Identifier: owner.Username, Password: req.Password, UserAgent: r.UserAgent(), IP: s.requestIP(r),
	})
	if err != nil {
		s.writeError(w, err)
		return
	}
	s.writeAuthResult(w, r, out, authExtras{})
}
