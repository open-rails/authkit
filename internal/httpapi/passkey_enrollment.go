package httpapi

import (
	jwt "github.com/golang-jwt/jwt/v5"
	"net/http"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

func (s *Service) passkeyEnrollmentCaller(w http.ResponseWriter, r *http.Request) (authflow.TwoFactorEnrollInput, bool) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" || !claims.TwoFAEnrollment || claims.SessionID != "" || claims.JTI == "" {
		fail(w, errmodel.CodeInvalidChallenge)
		return authflow.TwoFactorEnrollInput{}, false
	}
	return authflow.TwoFactorEnrollInput{UserID: claims.UserID, LoginChallenge: claims.JTI,
		Mode: authflow.FirstFactorOnly, Method: "passkey", UserAgent: r.UserAgent(), IP: s.requestIP(r)}, true
}

func (s *Service) handlePasskeyMFAEnrollBeginPOST(w http.ResponseWriter, r *http.Request) {
	in, ok := s.passkeyEnrollmentCaller(w, r)
	if !ok {
		return
	}
	creation, err := s.svc.BeginPasskeyMFAEnrollment(r.Context(), in)
	if err != nil {
		writeError(w, remap(err, map[error]errmodel.Code{jwt.ErrTokenUnverifiable: errmodel.CodeInvalidChallenge, jwt.ErrTokenInvalidClaims: errmodel.CodeInvalidChallenge}))
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

func (s *Service) handlePasskeyMFAEnrollFinishPOST(w http.ResponseWriter, r *http.Request) {
	in, ok := s.passkeyEnrollmentCaller(w, r)
	if !ok {
		return
	}
	body, err := readSmallBody(r)
	if err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	out, err := s.svc.FinishPasskeyMFAEnrollment(r.Context(), in, body)
	if err != nil {
		writeError(w, remap(err, map[error]errmodel.Code{jwt.ErrTokenUnverifiable: errmodel.CodeInvalidChallenge, jwt.ErrTokenInvalidClaims: errmodel.CodeInvalidChallenge}))
		return
	}
	s.writeAuthResult(w, r, out, authExtras{})
}
