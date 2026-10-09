package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/internal/oidcstate"
)

const oidcStepUpClockSkew = 2 * time.Minute

// handlePasswordStepUpPOST re-authenticates the session with the account's
// password, for an account without a second factor.
func (s *Service) handlePasswordStepUpPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := stepUpCaller(w, r)
	if !ok {
		return
	}
	var body PasswordRequest
	if err := decodeJSON(r, &body); err != nil || body.Password == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	// MFA-if-enrolled: a password never re-proves an account with a second
	// factor; it steps up with that factor (N1).
	if s.hasUsableMFA(r, claims.UserID) {
		s.requireStepUp(w, r, claims.UserID)
		return
	}
	if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, body.Password); verr != nil {
		// A legacy reset-required hash can never verify: the user must reset
		// it before stepping up with a password.
		passwordRejected(w, verr)
		return
	}
	if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
		serverErr(w, "step_up_failed", err)
		return
	}
	s.writeFresh(w, r, claims.UserID, claims.SessionID)
}

// handleTwoFactorStepUpSendPOST sends a step-up code to a second factor (the
// default one when no factor_id is named); an authenticator app needs none.
func (s *Service) handleTwoFactorStepUpSendPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := stepUpCaller(w, r)
	if !ok {
		return
	}
	var body TwoFactorSendRequest
	if err := decodeOptionalJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if !s.requireSecondFactor(w, r, claims.UserID) || s.rateLimitedByIdentifier(w, r, RLStepUp2FASend, claims.UserID) {
		return
	}
	if err := s.svc.Send2FAStepUpCode(r.Context(), claims.UserID, claims.SessionID, body.FactorID); err != nil {
		writeError(w, err)
		return
	}
	accepted(w)
}

// handleTwoFactorStepUpPOST re-authenticates the session with a second-factor
// code (sent by /me/step-up/2fa/send, or an authenticator app's) or a backup
// code.
func (s *Service) handleTwoFactorStepUpPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := stepUpCaller(w, r)
	if !ok {
		return
	}
	if s.rateLimitedByIdentifier(w, r, RL2FAVerify, claims.UserID) {
		return
	}
	var body TwoFactorStepUpRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	code := strings.TrimSpace(body.Code)
	if code == "" {
		fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("code"))
		return
	}
	if !s.requireSecondFactor(w, r, claims.UserID) {
		return
	}
	var valid bool
	var err error
	if body.BackupCode {
		valid, err = s.svc.VerifyBackupCode(r.Context(), claims.UserID, code)
	} else {
		valid, err = s.svc.Verify2FAStepUpCode(r.Context(), claims.UserID, claims.SessionID, body.FactorID, code)
	}
	if errmodel.CodeOf(err) == errmodel.CodeNotFound {
		writeError(w, err)
		return
	}
	if err != nil || !valid {
		fail(w, codeRejection(err))
		return
	}
	if err := s.svc.MarkSessionAuthenticatedWithMethods(r.Context(), claims.UserID, claims.SessionID, []string{"otp", "mfa"}); err != nil {
		serverErr(w, "step_up_failed", err)
		return
	}
	s.writeFresh(w, r, claims.UserID, claims.SessionID)
}

// stepUpCaller is the signed-in caller of a step-up route: a step-up
// re-authenticates a refresh session.
func stepUpCaller(w http.ResponseWriter, r *http.Request) (verify.Claims, bool) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return verify.Claims{}, false
	}
	return claims, true
}

// requireSecondFactor refuses a second-factor step-up for an account without
// one.
func (s *Service) requireSecondFactor(w http.ResponseWriter, r *http.Request, userID string) bool {
	enrolled, err := s.svc.HasUsableMFA(r.Context(), userID)
	if err != nil {
		serverErr(w, "load_2fa", err)
		return false
	}
	if !enrolled {
		fail(w, errmodel.CodeInvalidTwoFAMethod)
		return false
	}
	return true
}

// writeFresh answers a re-authenticated session's fresh AuthResult.
func (s *Service) writeFresh(w http.ResponseWriter, r *http.Request, userID, sessionID string) {
	res, err := s.freshAuthResult(w, r, userID, sessionID)
	if err != nil {
		serverErr(w, "token_issue_failed", err)
		return
	}
	writeAuthResult(w, res)
}

func (s *Service) handleOIDCStepUpStartPOST(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.PathValue("provider"))
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}

	var body ReturnToRequest
	_ = decodeJSON(r, &body)

	// #294: only a provider that proves a fresh interactive login (OIDC
	// max_age=0 checked against auth_time) is a step-up method. OAuth2 IdPs
	// silently re-authorize an approved app, so completing them proves nothing.
	p, known := s.provider(provider)
	if !known {
		fail(w, errmodel.CodeUnknownProvider)
		return
	}
	if !p.SupportsStepUp() {
		fail(w, errmodel.CodeInvalidTwoFAMethod)
		return
	}
	if !s.userHasLinkedIssuerProvider(r, claims.UserID, p.Issuer(), p.Name()) {
		fail(w, errmodel.CodeProviderNotLinked)
		return
	}
	if s.hasUsableMFA(r, claims.UserID) {
		s.requireStepUp(w, r, claims.UserID)
		return
	}
	s.startProviderFlow(w, r, p.Name(), flowStart{
		params: map[string]string{"max_age": "0"},
		stepUp: &oidcstate.StateData{
			StepUpUserID:    claims.UserID,
			StepUpSessionID: claims.SessionID,
			StepUpReturnTo:  SanitizeReturnTo(body.ReturnTo),
			StepUpStartedAt: time.Now().UTC(),
		},
	})
}

func (s *Service) userHasLinkedIssuerProvider(r *http.Request, userID, issuer, provider string) bool {
	exists, err := s.svc.HasProviderLink(r.Context(), userID, issuer, provider)
	return err == nil && exists
}

// completeOIDCStepUp finishes a step-up callback: the provider identity must
// be the session's own, freshly authenticated, on an account without a second
// factor. The result is the session's fresh AuthResult. It reports whether sd
// was a step-up.
func (s *Service) completeOIDCStepUp(w http.ResponseWriter, r *http.Request, sd oidcstate.StateData, provider, issuer, subject string, authTime time.Time) bool {
	if strings.TrimSpace(sd.StepUpUserID) == "" {
		return false
	}
	userID, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), issuer, subject)
	if err != nil || userID != sd.StepUpUserID {
		s.failBrowserFlow(w, r, &sd, provider, errmodel.E(errmodel.CodeProviderNotLinked))
		return true
	}
	if !validOIDCStepUpTime(sd.StepUpStartedAt, authTime, time.Now().UTC()) || s.hasUsableMFA(r, sd.StepUpUserID) {
		s.failBrowserFlow(w, r, &sd, provider, s.svc.StepUpRequired(r.Context(), sd.StepUpUserID))
		return true
	}
	if err := s.svc.MarkSessionAuthenticated(r.Context(), sd.StepUpUserID, sd.StepUpSessionID); err != nil {
		s.failBrowserFlow(w, r, &sd, provider, errmodel.Internal("step_up_failed", err))
		return true
	}
	res, err := s.freshAuthResult(w, r, sd.StepUpUserID, sd.StepUpSessionID)
	if err != nil {
		s.failBrowserFlow(w, r, &sd, provider, err)
		return true
	}
	s.emitBrowserResult(w, r, &sd, provider, res)
	return true
}

func validOIDCStepUpTime(startedAt, authTime, now time.Time) bool {
	if startedAt.IsZero() || authTime.IsZero() || authTime.After(now.Add(oidcStepUpClockSkew)) {
		return false
	}
	return !authTime.Before(startedAt.Add(-oidcStepUpClockSkew))
}

// requireStepUp answers step_up_required with how userID can step up.
func (s *Service) requireStepUp(w http.ResponseWriter, r *http.Request, userID string) {
	writeError(w, s.svc.StepUpRequired(r.Context(), userID))
}

// hasUsableMFA reports whether the account has an enabled second factor. A
// lookup failure counts as enrolled, so the password shortcut fails closed.
func (s *Service) hasUsableMFA(r *http.Request, userID string) bool {
	ok, err := s.svc.HasUsableMFA(r.Context(), userID)
	return ok || err != nil
}

func freshAuth(f authflow.SessionFreshness) FreshAuth {
	out := FreshAuth{
		StepUpRequiredForSensitiveActions: f.StepUpRequiredForSensitiveOps,
		StepUpRequiredInSeconds:           int64((max(f.TimeUntilStepUpRequired, 0) + time.Second - time.Nanosecond) / time.Second),
		AuthMethods:                       f.AuthMethods,
	}
	if out.AuthMethods == nil {
		out.AuthMethods = []string{}
	}
	if !f.LastAuthenticatedAt.IsZero() {
		out.LastAuthenticatedAt = &f.LastAuthenticatedAt
	}
	return out
}

// sanitizeReturnTo admits only a same-origin absolute path: a leading "/" but
// not "//" or "/\" (browsers read both as scheme-relative), no control
// characters, no scheme or host. Anything else becomes "/".
func SanitizeReturnTo(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\\\r\n\t") || !strings.HasPrefix(value, "/") ||
		strings.HasPrefix(value, "//") || strings.HasPrefix(value, "/\\") {
		return "/"
	}
	u, err := url.Parse(value)
	if err != nil || u == nil || u.IsAbs() || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return value
}

// requireSession is the AuthSession route tier (#412): the session or device
// key the caller's token was minted from must still be active. Logout,
// revoke-all, a password change, a ban and deletion revoke it, so a stolen
// token stops changing the account the moment any of them happens, instead of
// installing a credential that outlives them. A 2FA-enrollment token has no
// session; it reaches only the enrollment routes, where the engine checks its
// login proof. These routes are a user's own.
func (s *Service) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := callerClaims(r)
		switch {
		case err != nil, claims.TwoFAEnrollment:
		case !claims.IsUser():
			err = errmodel.E(errmodel.CodeForbidden)
		default:
			err = s.svc.CheckSession(r.Context(), claims)
		}
		if err != nil {
			writeError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// passwordRejected answers a failed CheckUserPassword: password_reset_required
// and server_busy as themselves, anything else invalid_password.
func passwordRejected(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errmodel.ErrPasswordResetRequired):
		fail(w, errmodel.CodePasswordResetRequired)
	case errmodel.CodeOf(err) == errmodel.CodeServerBusy:
		writeError(w, err)
	default:
		fail(w, errmodel.CodeInvalidPassword)
	}
}

// requireProvenContact answers 403 verification_required (metadata identifier,
// channel, reason=contact_unproven) while every address on the account is
// unproven: new login methods wait for a proof (ak#393). The frontend sends a
// code with POST /verify/request and confirms it at POST /verify/confirm.
func (s *Service) requireProvenContact(w http.ResponseWriter, r *http.Request, userID string) bool {
	if err := s.svc.RequireProvenContact(r.Context(), userID); err != nil {
		writeError(w, err)
		return false
	}
	return true
}
