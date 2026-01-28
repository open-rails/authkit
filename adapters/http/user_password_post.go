package authhttp

import (
	"net/http"

	pwhash "github.com/PaulFidika/authkit/password"
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

	hadPwd := s.svc.HasPassword(r.Context(), claims.UserID)
	if hadPwd && body.CurrentPassword == "" {
		badRequest(w, "current_password_required")
		return
	}

	var keep *string
	if claims.SessionID != "" {
		keep = &claims.SessionID
	}
	if err := s.svc.ChangePassword(r.Context(), claims.UserID, body.CurrentPassword, body.NewPassword, keep); err != nil {
		badRequest(w, "password_change_failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
