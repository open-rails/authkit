package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/internal/oidcstate"
)

const oidcStepUpClockSkew = 2 * time.Minute

func (s *Service) handlePasswordStepUpPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
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
		if errors.Is(verr, errmodel.ErrPasswordResetRequired) {
			// The stored hash can never verify (legacy reset-required); the user
			// cannot step up with a password and must reset it first.
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
	resp, err := s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
	if err != nil {
		serverErr(w, "token_issue_failed", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleTwoFactorStepUpPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		fail(w, errmodel.CodeUnauthenticated)
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
	if strings.TrimSpace(body.FactorID) != "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	method := strings.ToLower(strings.TrimSpace(body.Method))
	if method != "" && !authflow.ValidTwoFactorStepUpMethod(method) {
		fail(w, errmodel.CodeInvalidTwoFAMethod)
		return
	}

	if strings.TrimSpace(body.Code) == "" {
		destination, method, _, err := s.svc.Require2FAForStepUpMethod(r.Context(), claims.UserID, claims.SessionID, method)
		if err != nil {
			if method != "" {
				fail(w, errmodel.CodeInvalidTwoFAMethod)
				return
			}
			writeError(w, err)
			return
		}
		fail(w, errmodel.CodeTwoFARequired, errmodel.WithMetadata(map[string]any{
			"method":          method,
			"verification_id": contact.MaskDestination(destination),
		}))
		return
	}

	var valid bool
	var err error
	if body.BackupCode {
		valid, err = s.svc.VerifyBackupCode(r.Context(), claims.UserID, strings.TrimSpace(body.Code))
	} else {
		valid, err = s.svc.Verify2FAStepUpMethodCode(r.Context(), claims.UserID, claims.SessionID, method, strings.TrimSpace(body.Code))
	}
	if err != nil || !valid {
		fail(w, codeRejection(err))
		return
	}

	if err := s.svc.MarkSessionAuthenticatedWithMethods(r.Context(), claims.UserID, claims.SessionID, []string{"otp", "mfa"}); err != nil {
		serverErr(w, "step_up_failed", err)
		return
	}
	freshness, _ := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
	resp, err := s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
	if err != nil {
		serverErr(w, "token_issue_failed", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
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

func (s *Service) completeOIDCStepUp(w http.ResponseWriter, r *http.Request, sd oidcstate.StateData, provider, issuer, subject string, authTime time.Time) bool {
	if strings.TrimSpace(sd.StepUpUserID) == "" {
		return false
	}
	userID, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), issuer, subject)
	if err != nil || userID != sd.StepUpUserID {
		redirectStepUpResult(w, r, sd.StepUpReturnTo, "failed")
		return true
	}
	if !validOIDCStepUpTime(sd.StepUpStartedAt, authTime, time.Now().UTC()) || s.hasUsableMFA(r, sd.StepUpUserID) {
		redirectStepUpResult(w, r, sd.StepUpReturnTo, "failed")
		return true
	}
	if err := s.svc.MarkSessionAuthenticated(r.Context(), sd.StepUpUserID, sd.StepUpSessionID); err != nil {
		redirectStepUpResult(w, r, sd.StepUpReturnTo, "failed")
		return true
	}
	return s.emitStepUpResult(w, r, sd, provider)
}

// emitStepUpResult writes the success result shared by the OIDC and OAuth2 step-up
// completers: a fresh-token JSON body (tagged with the provider name) when JSON is
// requested, else a success redirect. Always returns true (request handled).
func (s *Service) emitStepUpResult(w http.ResponseWriter, r *http.Request, sd oidcstate.StateData, providerName string) bool {
	if strings.EqualFold(r.URL.Query().Get("format"), "json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		freshness, _ := s.svc.SessionFreshness(r.Context(), sd.StepUpUserID, sd.StepUpSessionID, time.Now())
		fresh, err := s.freshAccessTokenResponse(r, sd.StepUpUserID, sd.StepUpSessionID, freshness)
		if err != nil {
			redirectStepUpResult(w, r, sd.StepUpReturnTo, "failed")
			return true
		}
		writeJSON(w, http.StatusOK, OIDCStepUpResult{TokenSet: fresh.TokenSet, FreshAuth: fresh.FreshAuth, Provider: providerName})
		return true
	}
	redirectStepUpResult(w, r, sd.StepUpReturnTo, "success")
	return true
}

func validOIDCStepUpTime(startedAt, authTime, now time.Time) bool {
	if startedAt.IsZero() || authTime.IsZero() || authTime.After(now.Add(oidcStepUpClockSkew)) {
		return false
	}
	return !authTime.Before(startedAt.Add(-oidcStepUpClockSkew))
}

// requireFreshAuthOrPassword is the sensitive-action gate of AuthKit's own
// credential routes: the engine's CheckRecentSignIn (the gate
// verify.Sensitive applies to host routes), or, for an account without a
// second factor, a correct password in the request, which re-authenticates
// the session and returns a fresh token set.
func (s *Service) requireFreshAuthOrPassword(w http.ResponseWriter, r *http.Request, claims verify.Claims, password string) (bool, *StepUpResult) {
	err := s.svc.CheckRecentSignIn(r.Context(), claims)
	if err == nil {
		return true, nil
	}
	// MFA-if-enrolled: a password never clears the gate for an account with a
	// second factor (M5).
	if password == "" || errmodel.CodeOf(err) != errmodel.CodeStepUpRequired || s.hasUsableMFA(r, claims.UserID) {
		writeError(w, err)
		return false, nil
	}
	if s.rateLimited(w, r, RLPasswordStepUp) {
		return false, nil
	}
	if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, password); verr != nil {
		if errors.Is(verr, errmodel.ErrPasswordResetRequired) {
			fail(w, errmodel.CodePasswordResetRequired)
			return false, nil
		}
		fail(w, errmodel.CodeInvalidPassword)
		return false, nil
	}
	if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
		serverErr(w, "step_up_failed", err)
		return false, nil
	}
	freshness, _ := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
	fresh, err := s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
	if err != nil {
		serverErr(w, "token_issue_failed", err)
		return false, nil
	}
	return true, &fresh
}

// requireStepUp answers step_up_required with how userID can step up.
func (s *Service) requireStepUp(w http.ResponseWriter, r *http.Request, userID string) {
	writeError(w, s.svc.StepUpRequired(r.Context(), userID))
}

// freshAccessTokenResponse mints the re-authenticated session's access token.
func (s *Service) freshAccessTokenResponse(r *http.Request, userID, sessionID string, freshness authflow.SessionFreshness) (StepUpResult, error) {
	token, exp, err := s.svc.MintSessionAccessToken(r.Context(), userID, sessionID)
	if err != nil {
		return StepUpResult{}, err
	}
	return StepUpResult{TokenSet: iam.NewTokenSet(token, "", exp), FreshAuth: freshAuth(freshness)}, nil
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
		TimeUntilStepUpRequired:           int64((f.TimeUntilStepUpRequired + time.Second - time.Nanosecond) / time.Second),
		AuthMethods:                       f.AuthMethods,
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

func redirectStepUpResult(w http.ResponseWriter, r *http.Request, returnTo, status string) {
	target := SanitizeReturnTo(returnTo)
	u, err := url.Parse(target)
	if err != nil || u == nil {
		u = &url.URL{Path: "/"}
	}
	q := u.Query()
	q.Set("step_up", status)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// requireSession is the AuthSession route tier (#412): the session or device
// key the caller's token was minted from must still be active. Logout,
// revoke-all, a password change, a ban and deletion revoke it, so a stolen
// token stops changing the account the moment any of them happens, instead of
// installing a credential that outlives them. A 2FA-enrollment token has no
// session; it reaches only the enrollment routes, where the engine checks its
// login proof. These routes are a user's own: a delegated token passes the
// session check but not this tier.
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
