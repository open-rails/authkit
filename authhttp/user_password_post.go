package authhttp

import (
	"errors"
	"net/http"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handleUserPasswordPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeNotAuthenticated)
		return
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	if err := embedded.ValidatePassword(body.NewPassword); err != nil {
		writeError(w, err)
		return
	}

	var authMeta map[string]any
	if !verify.SensitiveClaims(claims) {
		if body.CurrentPassword == "" {
			s.requireStepUp(w, r, claims)
			return
		}
		if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, body.CurrentPassword); verr != nil {
			if errors.Is(verr, authkit.ErrPasswordResetRequired) {
				unauthorized(w, authkit.CodePasswordResetRequired)
				return
			}
			unauthorized(w, authkit.CodeInvalidPassword)
			return
		}
		if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
			serverErr(w, authkit.CodeStepUpFailed)
			return
		}
		freshness, _ := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
		var err error
		authMeta, err = s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
		if err != nil {
			serverErr(w, authkit.CodeTokenIssueFailed)
			return
		}
		delete(authMeta, "ok")
	}

	keep := keepSession(claims)
	hadPwd, err := s.svc.HasPassword(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, authkit.CodeDatabaseError)
		return
	}
	var changeErr error
	if hadPwd && body.CurrentPassword == "" {
		changeErr = s.svc.SetPasswordAfterFreshAuth(r.Context(), claims.UserID, body.NewPassword, keep)
	} else {
		changeErr = s.svc.ChangePassword(r.Context(), claims.UserID, body.CurrentPassword, body.NewPassword, keep)
	}
	if changeErr != nil {
		if errors.Is(changeErr, authkit.ErrPasswordResetRequired) {
			// The current password can never verify against a legacy
			// reset-required hash; route the user to the reset flow.
			badRequest(w, authkit.CodePasswordResetRequired)
			return
		}
		if code := embedded.ValidationErrorCode(changeErr); code != "" {
			badRequest(w, code)
			return
		}
		badRequest(w, authkit.CodePasswordChangeFailed)
		return
	}

	// A password step-up on the way in earned a fresh token set; otherwise
	// there is nothing to return.
	if len(authMeta) == 0 {
		noContent(w)
		return
	}
	writeJSON(w, http.StatusOK, authMeta)
}
