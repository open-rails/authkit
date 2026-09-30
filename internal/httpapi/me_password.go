package httpapi

import (
	"errors"
	"net/http"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// handleMePasswordPUT sets or changes the caller's password; other sessions
// end. 204, or 200 with the session's fresh AuthResult when the current
// password re-authenticated it.
func (s *Service) handleMePasswordPUT(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}

	var body PasswordChangeRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if body.CurrentPassword != "" && s.rateLimited(w, r, RLPasswordStepUp) {
		return
	}
	if err := s.svc.ValidatePassword(body.NewPassword); err != nil {
		writeError(w, err)
		return
	}

	// A stale session may re-authenticate with the current password on the
	// way; the answer is then its fresh AuthResult.
	reauthenticated := false
	if err := s.svc.CheckRecentSignIn(r.Context(), claims); err != nil {
		// MFA-if-enrolled: the current password alone never clears the gate
		// for an account with a second factor (M5).
		if errmodel.CodeOf(err) != errmodel.CodeStepUpRequired || body.CurrentPassword == "" || claims.SessionID == "" || s.hasUsableMFA(r, claims.UserID) {
			writeError(w, err)
			return
		}
		if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, body.CurrentPassword); verr != nil {
			passwordRejected(w, verr)
			return
		}
		if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
			serverErr(w, "step_up_failed", err)
			return
		}
		reauthenticated = true
	}

	keep := keepCredential(claims)
	hadPwd, err := s.svc.HasPassword(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "database_error", err)
		return
	}
	var changeErr error
	if hadPwd && body.CurrentPassword == "" {
		changeErr = s.svc.SetPasswordAfterFreshAuth(r.Context(), claims.UserID, body.NewPassword, keep)
	} else {
		changeErr = s.svc.ChangePassword(r.Context(), claims.UserID, body.CurrentPassword, body.NewPassword, keep)
	}
	if changeErr != nil {
		if errors.Is(changeErr, errmodel.ErrPasswordResetRequired) {
			// The current password can never verify against a legacy
			// reset-required hash; route the user to the reset flow.
			fail(w, errmodel.CodePasswordResetRequired)
			return
		}
		if authflow.ValidationErrorCode(changeErr) != "" {
			writeError(w, changeErr)
			return
		}
		fail(w, errmodel.CodePasswordChangeFailed)
		return
	}

	if !reauthenticated {
		noContent(w)
		return
	}
	s.writeFreshAuthResult(w, r, claims.UserID, claims.SessionID)
}
