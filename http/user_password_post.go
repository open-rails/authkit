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
		unauthorized(w, ErrNotAuthenticated)
		return
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := core.ValidatePassword(body.NewPassword); err != nil {
		badRequest(w, ErrorCode(core.ValidationErrorCode(err)))
		return
	}

	var authMeta map[string]any
	if !SensitiveClaims(claims) {
		if body.CurrentPassword == "" {
			s.requireStepUp(w, r, claims)
			return
		}
		if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, body.CurrentPassword); verr != nil {
			if errors.Is(verr, core.ErrPasswordResetRequired) {
				unauthorized(w, ErrPasswordResetRequired)
				return
			}
			unauthorized(w, ErrInvalidPassword)
			return
		}
		if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
			serverErr(w, ErrStepUpFailed)
			return
		}
		freshness, _ := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
		var err error
		authMeta, err = s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
		if err != nil {
			serverErr(w, ErrTokenIssueFailed)
			return
		}
		delete(authMeta, "ok")
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
			badRequest(w, ErrPasswordResetRequired)
			return
		}
		if code := ErrorCode(core.ValidationErrorCode(changeErr)); code != "" {
			badRequest(w, code)
			return
		}
		badRequest(w, ErrPasswordChangeFailed)
		return
	}

	resp := map[string]any{"ok": true}
	for k, v := range authMeta {
		resp[k] = v
	}
	writeJSON(w, http.StatusOK, resp)
}
