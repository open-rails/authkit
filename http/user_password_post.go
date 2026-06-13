package authhttp

import (
	"errors"
	"net/http"
	"time"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleUserPasswordPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLUserPasswordChange) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "not_authenticated")
		return
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, "invalid_request")
		return
	}
	if err := core.ValidatePassword(body.NewPassword); err != nil {
		badRequest(w, core.ValidationErrorCode(err))
		return
	}

	freshness, err := s.svc.RequireFreshSession(r.Context(), claims.UserID, claims.SessionID, time.Now())
	if err != nil {
		if errors.Is(err, core.ErrReauthenticationRequired) && body.CurrentPassword != "" {
			if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, body.CurrentPassword); verr != nil {
				if errors.Is(verr, core.ErrPasswordResetRequired) {
					unauthorized(w, "password_reset_required")
					return
				}
				unauthorized(w, "invalid_password")
				return
			}
			if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
				serverErr(w, "reauth_failed")
				return
			}
		} else if errors.Is(err, core.ErrReauthenticationRequired) {
			s.reauthRequired(w, r, claims)
			return
		} else {
			unauthorized(w, "not_authenticated")
			return
		}
	} else if freshness.ReauthRequiredForSensitiveOps {
		s.reauthRequired(w, r, claims)
		return
	}

	var keep *string
	if claims.SessionID != "" {
		keep = &claims.SessionID
	}
	hadPwd := s.svc.HasPassword(r.Context(), claims.UserID)
	var changeErr error
	if hadPwd && body.CurrentPassword == "" {
		changeErr = s.svc.SetPasswordAfterFreshAuth(r.Context(), claims.UserID, body.NewPassword, keep)
	} else {
		changeErr = s.svc.ChangePassword(r.Context(), claims.UserID, body.CurrentPassword, body.NewPassword, keep)
	}
	if changeErr != nil {
		if errors.Is(changeErr, core.ErrPasswordResetRequired) {
			// The current password can never verify against a legacy
			// reset-required hash; route the user to the reset flow.
			badRequest(w, "password_reset_required")
			return
		}
		if code := core.ValidationErrorCode(changeErr); code != "" {
			badRequest(w, code)
			return
		}
		badRequest(w, "password_change_failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
