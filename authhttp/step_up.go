package authhttp

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/oidckit"
)

const oidcStepUpClockSkew = 2 * time.Minute

func (s *Service) handlePasswordStepUpPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		unauthorized(w, authkit.CodeNotAuthenticated)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil || body.Password == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, body.Password); verr != nil {
		if errors.Is(verr, authkit.ErrPasswordResetRequired) {
			// The stored hash can never verify (legacy reset-required); the user
			// cannot step up with a password and must reset it first.
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
	resp, err := s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
	if err != nil {
		serverErr(w, authkit.CodeTokenIssueFailed)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleTwoFactorStepUpPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		unauthorized(w, authkit.CodeNotAuthenticated)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RL2FAVerify, claims.UserID) {
		return
	}

	var body struct {
		Code       string `json:"code"`
		Method     string `json:"method"`
		FactorID   string `json:"factor_id"`
		BackupCode bool   `json:"backup_code"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	if strings.TrimSpace(body.FactorID) != "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	method := strings.ToLower(strings.TrimSpace(body.Method))
	if method != "" && !embedded.ValidTwoFactorStepUpMethod(method) {
		badRequest(w, authkit.CodeInvalidTwoFAMethod)
		return
	}

	if strings.TrimSpace(body.Code) == "" {
		destination, method, _, err := s.svc.Require2FAForStepUpMethod(r.Context(), claims.UserID, claims.SessionID, method)
		if err != nil {
			if method != "" {
				badRequest(w, authkit.CodeInvalidTwoFAMethod)
				return
			}
			writeError(w, err)
			return
		}
		sendErrData(w, http.StatusForbidden, authkit.CodeTwoFARequired, map[string]any{
			"method":          method,
			"verification_id": embedded.MaskDestination(destination),
		})
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
		unauthorized(w, authkit.CodeInvalidCode)
		return
	}

	if err := s.svc.MarkSessionAuthenticatedWithMethods(r.Context(), claims.UserID, claims.SessionID, []string{"otp", "mfa"}); err != nil {
		serverErr(w, authkit.CodeStepUpFailed)
		return
	}
	freshness, _ := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
	resp, err := s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
	if err != nil {
		serverErr(w, authkit.CodeTokenIssueFailed)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleOIDCStepUpStartPOST(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.PathValue("provider"))
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		unauthorized(w, authkit.CodeNotAuthenticated)
		return
	}

	var body struct {
		ReturnTo string `json:"return_to"`
	}
	_ = decodeJSON(r, &body)

	// #294: only a provider that proves a fresh interactive login (OIDC
	// max_age=0 checked against auth_time) is a step-up method. OAuth2 IdPs
	// silently re-authorize an approved app, so completing them proves nothing.
	p, known := s.provider(provider)
	if !known {
		badRequest(w, authkit.CodeUnknownProvider)
		return
	}
	if !p.SupportsStepUp() {
		badRequest(w, authkit.CodeInvalidTwoFAMethod)
		return
	}
	if !s.userHasLinkedIssuerProvider(r, claims.UserID, p.Issuer(), p.Name()) {
		badRequest(w, authkit.CodeProviderNotLinked)
		return
	}
	s.startProviderFlow(w, r, p.Name(), flowStart{
		params: map[string]string{"max_age": "0"},
		stepUp: &oidckit.StateData{
			StepUpUserID:    claims.UserID,
			StepUpSessionID: claims.SessionID,
			StepUpReturnTo:  sanitizeReturnTo(body.ReturnTo),
			StepUpStartedAt: time.Now().UTC(),
		},
	})
}

func (s *Service) userHasLinkedIssuerProvider(r *http.Request, userID, issuer, provider string) bool {
	exists, err := s.svc.HasProviderLink(r.Context(), userID, issuer, provider)
	return err == nil && exists
}

func (s *Service) completeOIDCStepUp(w http.ResponseWriter, r *http.Request, sd oidckit.StateData, provider, issuer, subject string, authTime time.Time) bool {
	if strings.TrimSpace(sd.StepUpUserID) == "" {
		return false
	}
	userID, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), issuer, subject)
	if err != nil || userID != sd.StepUpUserID {
		redirectStepUpResult(w, r, sd.StepUpReturnTo, "failed")
		return true
	}
	if !validOIDCStepUpTime(sd.StepUpStartedAt, authTime, time.Now().UTC()) {
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
func (s *Service) emitStepUpResult(w http.ResponseWriter, r *http.Request, sd oidckit.StateData, providerName string) bool {
	if strings.EqualFold(r.URL.Query().Get("format"), "json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		freshness, _ := s.svc.SessionFreshness(r.Context(), sd.StepUpUserID, sd.StepUpSessionID, time.Now())
		body, err := s.freshAccessTokenResponse(r, sd.StepUpUserID, sd.StepUpSessionID, freshness)
		if err != nil {
			redirectStepUpResult(w, r, sd.StepUpReturnTo, "failed")
			return true
		}
		body["provider"] = providerName
		writeJSON(w, http.StatusOK, body)
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

func (s *Service) requireFreshAuthOrPassword(w http.ResponseWriter, r *http.Request, claims verify.Claims, password string) (bool, map[string]any) {
	if verify.SensitiveClaims(claims) {
		return true, nil
	}
	if password != "" {
		if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, password); verr != nil {
			if errors.Is(verr, authkit.ErrPasswordResetRequired) {
				unauthorized(w, authkit.CodePasswordResetRequired)
				return false, nil
			}
			unauthorized(w, authkit.CodeInvalidPassword)
			return false, nil
		}
		if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
			serverErr(w, authkit.CodeStepUpFailed)
			return false, nil
		}
		freshness, _ := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
		body, err := s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
		if err != nil {
			serverErr(w, authkit.CodeTokenIssueFailed)
			return false, nil
		}
		return true, body
	}
	s.requireStepUp(w, r, claims)
	return false, nil
}

func (s *Service) requireStepUp(w http.ResponseWriter, r *http.Request, claims verify.Claims) {
	methods, err := s.stepUpMethods(r, claims.UserID)
	if err != nil {
		serverErr(w, authkit.CodeDatabaseError)
		return
	}
	metadata := map[string]any{
		"step_up_methods": methods,
		"max_age_seconds": int64(embedded.SensitiveActionFreshAuthWindow.Seconds()),
	}
	if twoFA := s.stepUpTwoFactorOptions(r, claims.UserID); twoFA != nil {
		metadata["step_up_2fa"] = twoFA
		// User has usable 2FA → MFA-if-enrolled means a password step-up won't
		// clear the gate; tell the client to route to 2FA.
		metadata["mfa_required"] = true
	}
	sendErrData(w, http.StatusForbidden, authkit.CodeStepUpRequired, metadata)
}

func (s *Service) freshAccessTokenResponse(r *http.Request, userID, sessionID string, freshness embedded.SessionFreshness) (map[string]any, error) {
	token, exp, err := s.svc.MintAccessToken(r.Context(), userID, map[string]any{"sid": sessionID})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"token_set":  authkit.TokenSet{AccessToken: token, TokenType: "Bearer", ExpiresIn: int64(time.Until(exp).Seconds())},
		"fresh_auth": sessionFreshnessResponse(freshness),
	}, nil
}

func (s *Service) stepUpMethods(r *http.Request, userID string) ([]string, error) {
	hasPassword, err := s.svc.HasPassword(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	settings, _ := s.svc.Get2FASettings(r.Context(), userID)
	providerSlugs, _ := s.svc.ProviderSlugs(r.Context(), userID)
	return embedded.StepUpMethods(hasPassword, settings, providerSlugs, s.providerSupportsStepUp), nil
}

func (s *Service) stepUpTwoFactorOptions(r *http.Request, userID string) *authkit.StepUpTwoFactorOptions {
	settings, err := s.svc.Get2FASettings(r.Context(), userID)
	if err != nil {
		return nil
	}
	// The email destination is fetched only when an enabled email factor needs
	// it, so users without one incur no user lookup.
	email := ""
	for _, factor := range settings.Factors {
		if factor.Enabled && strings.EqualFold(factor.Method, "email") {
			if user, err := s.svc.AdminGetUser(r.Context(), userID); err == nil && user != nil && user.Email != nil {
				email = *user.Email
			}
			break
		}
	}
	return embedded.StepUpTwoFactorOptions(settings, email)
}

func sessionFreshnessResponse(f embedded.SessionFreshness) map[string]any {
	out := map[string]any{
		"step_up_required_for_sensitive_actions": f.StepUpRequiredForSensitiveOps,
		"time_until_step_up_required":            int64((f.TimeUntilStepUpRequired + time.Second - time.Nanosecond) / time.Second),
	}
	if !f.LastAuthenticatedAt.IsZero() {
		out["last_authenticated_at"] = f.LastAuthenticatedAt.UTC().Format(time.RFC3339)
	}
	if len(f.AuthMethods) > 0 {
		out["auth_methods"] = f.AuthMethods
	}
	return out
}

func sanitizeReturnTo(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\\\r\n\t") || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "/"
	}
	u, err := url.Parse(value)
	if err != nil || u == nil || u.IsAbs() || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return value
}

func redirectStepUpResult(w http.ResponseWriter, r *http.Request, returnTo, status string) {
	target := sanitizeReturnTo(returnTo)
	u, err := url.Parse(target)
	if err != nil || u == nil {
		u = &url.URL{Path: "/"}
	}
	q := u.Query()
	q.Set("step_up", status)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
