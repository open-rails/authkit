package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

func (s *Service) handleUserPasswordPOST(w http.ResponseWriter, r *http.Request) {
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

	var stepUp *StepUpResult
	if err := s.svc.CheckRecentSignIn(r.Context(), claims); err != nil {
		// MFA-if-enrolled: the current password alone never clears the gate
		// for an account with a second factor (M5).
		if errmodel.CodeOf(err) != errmodel.CodeStepUpRequired || body.CurrentPassword == "" || s.hasUsableMFA(r, claims.UserID) {
			writeError(w, err)
			return
		}
		if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, body.CurrentPassword); verr != nil {
			if errors.Is(verr, errmodel.ErrPasswordResetRequired) {
				fail(w, errmodel.CodePasswordResetRequired)
				return
			}
			fail(w, errmodel.CodeInvalidPassword)
			return
		}
		if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
			serverErr(w, "step_up_failed", err)
			return
		}
		freshness, _ := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
		fresh, err := s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
		if err != nil {
			serverErr(w, "token_issue_failed", err)
			return
		}
		stepUp = &fresh
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

	// A password step-up on the way in earned a fresh token set; otherwise
	// there is nothing to return.
	if stepUp == nil {
		noContent(w)
		return
	}
	writeJSON(w, http.StatusOK, stepUp)
}
