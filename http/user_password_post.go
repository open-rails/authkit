package authhttp

import (
	"errors"
	"net/http"
	"time"

	core "github.com/open-rails/authkit/core"
	pwhash "github.com/open-rails/authkit/password"
)

func (s *Service) handleUserPasswordPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLUserPasswordChange) {
		tooMany(w)
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
	if err := decodeJSON(r, &body); err != nil || pwhash.Validate(body.NewPassword) != nil {
		badRequest(w, "invalid_request")
		return
	}

	freshness, err := s.svc.RequireFreshSession(r.Context(), claims.UserID, claims.SessionID, time.Now())
	if err != nil {
		if errors.Is(err, core.ErrReauthenticationRequired) && body.CurrentPassword != "" {
			if !s.svc.VerifyUserPassword(r.Context(), claims.UserID, body.CurrentPassword) {
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
		badRequest(w, "password_change_failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
