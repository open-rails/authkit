package httpapi

import (
	"errors"
	"net/http"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// The caller's second factors. POST /me/2fa/setup starts a factor and POST
// /me/2fa/factors adds it: the engine's one enrollment flow (EnrollTwoFactor)
// split at its code. An enrollment token (AuthResult enrollment_required)
// reaches both; adding its first factor finishes that sign-in.

func (s *Service) handleMe2FAGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	settings, err := s.svc.Get2FASettings(r.Context(), claims.UserID)
	if err != nil {
		writeJSON(w, http.StatusOK, TwoFactorStatus{Factors: []TwoFactorFactor{}, AllowedMethods: s.svc.TwoFactorMethods()})
		return
	}
	writeJSON(w, http.StatusOK, TwoFactorStatus{
		Enabled:              settings.Enabled,
		Factors:              twoFactorFactorResponses(settings.Factors),
		AllowedMethods:       s.svc.TwoFactorMethods(),
		BackupCodesRemaining: len(settings.BackupCodes),
	})
}

// handleMe2FASetupPOST starts a factor: a code to the account's email or the
// given phone, or an authenticator app's secret.
func (s *Service) handleMe2FASetupPOST(w http.ResponseWriter, r *http.Request) {
	claims, scope, ok := s.enrollmentCaller(w, r)
	if !ok {
		return
	}
	var req TwoFactorSetupRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	method, phone := strings.ToLower(strings.TrimSpace(req.Method)), derefTrim(req.PhoneNumber)
	// Anti-spam velocity on the code-sending starts (authkit owns velocity).
	switch {
	case method == "sms" && strings.HasPrefix(phone, "+"):
		if s.rateLimited(w, r, RL2FAStartPhone) || s.rateLimitedByIdentifier(w, r, RL2FAStartPhone, contact.NormalizePhone(phone)) {
			return
		}
	case method == "totp":
		if s.rateLimited(w, r, RL2FAStartTOTP) {
			return
		}
	case method == "email":
		if s.rateLimited(w, r, RL2FAStartEmail) || s.rateLimitedByIdentifier(w, r, RL2FAStartEmail, claims.UserID) {
			return
		}
	}
	out, ok := s.enrollTwoFactor(w, r, s.enrollInput(r, claims, scope, method, "", phone, false))
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	setup := TwoFactorSetup{Method: out.Method}
	switch out.Kind {
	case authflow.TwoFactorEnrollCodeSent:
		masked := contact.MaskDestination(out.Destination)
		setup.Destination = &masked
	case authflow.TwoFactorEnrollTOTPStarted:
		setup.Secret, setup.OTPAuthURI = &out.Secret, &out.OTPAuthURI
	}
	writeJSON(w, http.StatusOK, setup)
}

// handleMe2FAFactorsPOST adds the factor its setup code proves. The first
// factor's backup codes are shown once. Auth is the sign-in an enrollment
// token finished, or the session's fresh token when the code re-verified it.
func (s *Service) handleMe2FAFactorsPOST(w http.ResponseWriter, r *http.Request) {
	claims, scope, ok := s.enrollmentCaller(w, r)
	if !ok {
		return
	}
	var req TwoFactorFactorCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	code := strings.TrimSpace(req.Code)
	if code == "" {
		fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("code"))
		return
	}
	method := strings.ToLower(strings.TrimSpace(req.Method))
	out, ok := s.enrollTwoFactor(w, r, s.enrollInput(r, claims, scope, method, code, derefTrim(req.PhoneNumber), req.Default))
	if !ok {
		return
	}
	created := TwoFactorFactorCreated{Factor: twoFactorFactorResponse(out.Factor), BackupCodes: out.BackupCodes}
	var auth AuthResult
	var err error
	switch {
	case out.Login != nil:
		auth, err = s.authResult(w, r, *out.Login, authExtras{})
	case out.SessionVerified:
		// The code verified this session: hand back a token whose assurance
		// claims match what its next refresh will carry (#389).
		auth, err = s.freshAuthResult(w, r, claims.UserID, claims.SessionID)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	if auth.Status != "" {
		created.Auth = &auth
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, created)
}

// handleMe2FAFactorPATCH makes a factor the default. A factor stops being the
// default only when another becomes it.
func (s *Service) handleMe2FAFactorPATCH(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	var req TwoFactorFactorUpdateRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if req.Default {
		factor, err := s.svc.SetDefault2FAFactor(r.Context(), claims.UserID, id)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, twoFactorFactorResponse(factor))
		return
	}
	settings, err := s.svc.Get2FASettings(r.Context(), claims.UserID)
	if err != nil {
		fail(w, errmodel.CodeNotFound)
		return
	}
	for _, factor := range settings.Factors {
		if factor.ID != id {
			continue
		}
		if factor.IsDefault {
			fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("default"))
			return
		}
		writeJSON(w, http.StatusOK, twoFactorFactorResponse(factor))
		return
	}
	fail(w, errmodel.CodeNotFound)
}

// handleMe2FAFactorDELETE removes a factor; the last one disables MFA and the
// roles that require it. An absent factor is already removed.
func (s *Service) handleMe2FAFactorDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	err := s.svc.Disable2FAFactor(r.Context(), claims.UserID, strings.TrimSpace(r.PathValue("id")))
	if err != nil && errmodel.CodeOf(err) != errmodel.CodeNotFound {
		writeError(w, err)
		return
	}
	noContent(w)
}

// handleMe2FADELETE removes every factor, and the roles that require MFA.
func (s *Service) handleMe2FADELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	if err := s.svc.Disable2FA(r.Context(), claims.UserID); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

// handleMe2FABackupCodesPOST replaces the backup codes, shown once.
func (s *Service) handleMe2FABackupCodesPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	if !s.requireSecondFactor(w, r, claims.UserID) {
		return
	}
	backupCodes, err := s.svc.RegenerateBackupCodes(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "regenerate_codes_failed", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, BackupCodes{BackupCodes: backupCodes})
}

// enrollmentCaller authorizes a factor's setup and creation. An enrollment
// token may fill only the account's first factor, with no step-up (the engine
// checks its login proof); a session needs a proven contact and a recent
// sign-in.
func (s *Service) enrollmentCaller(w http.ResponseWriter, r *http.Request) (verify.Claims, authflow.TwoFactorEnrollmentScope, bool) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return claims, authflow.TwoFactorEnrollmentScope{}, false
	}
	scope, err := s.svc.BeginTwoFactorEnrollment(r.Context(), claims.UserID, claims.TwoFAEnrollment, claims.SessionID)
	if err != nil {
		writeError(w, err)
		return claims, scope, false
	}
	if !claims.TwoFAEnrollment {
		if !s.requireProvenContact(w, r, claims.UserID) {
			return claims, scope, false
		}
		// A token minted before enrollment must not hide the account's
		// current MFA requirement.
		claims.MFAEnrolled = scope.HasFactors
		if err := s.svc.CheckRecentSignIn(r.Context(), claims); err != nil {
			writeError(w, err)
			return claims, scope, false
		}
	}
	return claims, scope, true
}

func (s *Service) enrollInput(r *http.Request, claims verify.Claims, scope authflow.TwoFactorEnrollmentScope, method, code, phone string, makeDefault bool) authflow.TwoFactorEnrollInput {
	challenge := ""
	if claims.TwoFAEnrollment {
		challenge = claims.JTI
	}
	return authflow.TwoFactorEnrollInput{
		LoginChallenge: challenge, SessionID: claims.SessionID, UserAgent: r.UserAgent(), IP: s.requestIP(r),
		UserID: claims.UserID, Mode: scope.Mode, Method: method, Code: code, PhoneNumber: phone, MakeDefault: makeDefault,
	}
}

func (s *Service) enrollTwoFactor(w http.ResponseWriter, r *http.Request, in authflow.TwoFactorEnrollInput) (authflow.TwoFactorEnrollOutcome, bool) {
	out, err := s.svc.EnrollTwoFactor(r.Context(), in)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenUnverifiable) || errors.Is(err, jwt.ErrTokenInvalidClaims) {
			fail(w, errmodel.CodeInvalidChallenge)
		} else {
			writeError(w, err)
		}
		return out, false
	}
	return out, true
}

func derefTrim(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func twoFactorFactorResponses(factors []authflow.TwoFactorFactor) []TwoFactorFactor {
	out := make([]TwoFactorFactor, 0, len(factors))
	for _, factor := range factors {
		out = append(out, twoFactorFactorResponse(factor))
	}
	return out
}

func twoFactorFactorResponse(factor authflow.TwoFactorFactor) TwoFactorFactor {
	out := TwoFactorFactor{ID: factor.ID, Method: factor.Method, IsDefault: factor.IsDefault}
	destination := factor.Email
	if factor.Method == "sms" {
		destination = factor.PhoneNumber
	}
	if destination != nil && factor.Method != "totp" {
		masked := contact.MaskDestination(*destination)
		out.Destination = &masked
	}
	return out
}
