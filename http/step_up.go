package authhttp

import (
	"errors"
	authkit "github.com/open-rails/authkit"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/db"
	oidckit "github.com/open-rails/authkit/oidc"
)

const oidcStepUpClockSkew = 2 * time.Minute

func ptr(s string) *string { return &s }

func (s *Service) handlePasswordStepUpPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil || body.Password == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, body.Password); verr != nil {
		if errors.Is(verr, authkit.ErrPasswordResetRequired) {
			// The stored hash can never verify (legacy reset-required); the user
			// cannot step up with a password and must reset it first.
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
	resp, err := s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
	if err != nil {
		serverErr(w, ErrTokenIssueFailed)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleTwoFactorStepUpPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		unauthorized(w, ErrNotAuthenticated)
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
		badRequest(w, ErrInvalidRequest)
		return
	}
	if strings.TrimSpace(body.FactorID) != "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	method := strings.ToLower(strings.TrimSpace(body.Method))
	if method != "" && !validTwoFactorStepUpMethod(method) {
		badRequest(w, ErrInvalidMethod)
		return
	}

	if strings.TrimSpace(body.Code) == "" {
		destination, method, _, err := s.svc.Require2FAForStepUpMethod(r.Context(), claims.UserID, claims.SessionID, method)
		if err != nil {
			if method != "" {
				badRequest(w, ErrInvalidMethod)
				return
			}
			if s.handleDeliveryError(w, r, "step_up_2fa", "send_2fa_code", err) {
				return
			}
			serverErr(w, ErrTwoFASendFailed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"requires_2fa":    true,
			"method":          method,
			"verification_id": obfuscateVerificationID(destination),
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
		unauthorized(w, ErrInvalidCode)
		return
	}

	if err := s.svc.MarkSessionAuthenticatedWithMethods(r.Context(), claims.UserID, claims.SessionID, []string{"otp", "mfa"}); err != nil {
		serverErr(w, ErrStepUpFailed)
		return
	}
	freshness, _ := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
	resp, err := s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
	if err != nil {
		serverErr(w, ErrTokenIssueFailed)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) handleOIDCStepUpStartPOST(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.PathValue("provider"))
	if cfg, ok := s.oauth2Provider(provider); ok {
		s.handleOAuthStepUpStartPOST(w, r, cfg.Name)
		return
	}
	if s.rateLimited(w, r, RLOIDCStart) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}

	var body struct {
		ReturnTo string `json:"return_to"`
	}
	_ = decodeJSON(r, &body)

	manager := s.oidcManager()
	issuer, ok := manager.IssuerFor(provider)
	if !ok || strings.TrimSpace(issuer) == "" {
		badRequest(w, ErrUnknownProvider)
		return
	}
	if !s.userHasLinkedIssuerProvider(r, claims.UserID, issuer, provider) {
		badRequest(w, ErrProviderNotLinked)
		return
	}

	state := randB64(32)
	nonce := randB64(16)
	verifier := ""
	challenge := ""
	if pc, ok := manager.Provider(provider); ok && pc.PKCE {
		var err error
		verifier, challenge, err = oidckit.GeneratePKCE()
		if err != nil {
			serverErr(w, ErrPKCEGenerationFailed)
			return
		}
	}
	redirectURI := s.buildRedirectURI(r, provider)
	// AK F3: bind state to this browser (CSRF defense).
	s.setStateCookie(w, r, state)
	startedAt := time.Now().UTC()
	authURL, err := manager.BeginWithAuthParams(r.Context(), provider, state, nonce, challenge, redirectURI, map[string]string{"max_age": "0"})
	if err != nil {
		badRequest(w, ErrOIDCBeginFailed)
		return
	}
	if err := s.stateCache().Put(r.Context(), state, oidckit.StateData{
		Provider:        provider,
		Verifier:        verifier,
		Nonce:           nonce,
		RedirectURI:     redirectURI,
		StepUpUserID:    claims.UserID,
		StepUpSessionID: claims.SessionID,
		StepUpReturnTo:  sanitizeStepUpReturnTo(body.ReturnTo),
		StepUpStartedAt: startedAt,
	}); err != nil {
		serverErr(w, ErrStateStoreFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"auth_url": authURL, "state": state})
}

func (s *Service) userHasLinkedIssuerProvider(r *http.Request, userID, issuer, provider string) bool {
	pg := s.svc.Postgres()
	if pg == nil {
		return false
	}
	exists, err := db.New(db.ForSchema(pg, s.svc.Schema())).UserProviderLinkExists(r.Context(), db.UserProviderLinkExistsParams{
		UserID:       strings.TrimSpace(userID),
		Issuer:       strings.TrimSpace(issuer),
		ProviderSlug: ptr(strings.TrimSpace(provider)),
	})
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
	if strings.EqualFold(r.URL.Query().Get("format"), "json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		freshness, _ := s.svc.SessionFreshness(r.Context(), sd.StepUpUserID, sd.StepUpSessionID, time.Now())
		body, err := s.freshAccessTokenResponse(r, sd.StepUpUserID, sd.StepUpSessionID, freshness)
		if err != nil {
			redirectStepUpResult(w, r, sd.StepUpReturnTo, "failed")
			return true
		}
		body["provider"] = provider
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

func (s *Service) requireFreshAuthOrPassword(w http.ResponseWriter, r *http.Request, claims Claims, password string) (bool, map[string]any) {
	if SensitiveClaims(claims) {
		return true, nil
	}
	if password != "" {
		if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, password); verr != nil {
			if errors.Is(verr, authkit.ErrPasswordResetRequired) {
				unauthorized(w, ErrPasswordResetRequired)
				return false, nil
			}
			unauthorized(w, ErrInvalidPassword)
			return false, nil
		}
		if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
			serverErr(w, ErrStepUpFailed)
			return false, nil
		}
		freshness, _ := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
		body, err := s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
		if err != nil {
			serverErr(w, ErrTokenIssueFailed)
			return false, nil
		}
		delete(body, "ok")
		return true, body
	}
	s.requireStepUp(w, r, claims)
	return false, nil
}

func (s *Service) requireStepUp(w http.ResponseWriter, r *http.Request, claims Claims) {
	metadata := map[string]any{
		"step_up_methods": s.stepUpMethods(r, claims.UserID),
		"max_age_seconds": int64(embedded.SensitiveActionFreshAuthWindow.Seconds()),
	}
	if twoFA := s.stepUpTwoFactorOptions(r, claims.UserID); twoFA != nil {
		metadata["step_up_2fa"] = twoFA
		// User has usable 2FA → MFA-if-enrolled means a password step-up won't
		// clear the gate; tell the client to route to 2FA.
		metadata["mfa_required"] = true
	}
	sendErrData(w, http.StatusForbidden, ErrStepUpRequired, metadata)
}

func (s *Service) freshAccessTokenResponse(r *http.Request, userID, sessionID string, freshness embedded.SessionFreshness) (map[string]any, error) {
	token, exp, err := s.svc.IssueAccessToken(r.Context(), userID, "", map[string]any{"sid": sessionID})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"ok":           true,
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int64(time.Until(exp).Seconds()),
		"fresh_auth":   sessionFreshnessResponse(freshness),
	}, nil
}

func (s *Service) stepUpMethods(r *http.Request, userID string) []string {
	methods := []string{}
	if s.svc.HasPassword(r.Context(), userID) {
		methods = append(methods, "password")
	}
	if settings, err := s.svc.Get2FASettings(r.Context(), userID); err == nil && settings != nil && settings.Enabled {
		methods = append(methods, "2fa")
	}
	pg := s.svc.Postgres()
	if pg == nil {
		return methods
	}
	providers, err := db.New(db.ForSchema(pg, s.svc.Schema())).UserProviderSlugsDistinct(r.Context(), strings.TrimSpace(userID))
	if err != nil {
		return methods
	}
	for _, provider := range providers {
		if _, ok := s.oidcManager().IssuerFor(provider); ok {
			methods = append(methods, provider)
		}
	}
	return methods
}

type stepUpTwoFactorOptionsResponse struct {
	Methods       []string                        `json:"methods,omitempty"`
	DefaultMethod string                          `json:"default_method,omitempty"`
	Options       []stepUpTwoFactorOptionResponse `json:"options,omitempty"`
}

type stepUpTwoFactorOptionResponse struct {
	Method         string `json:"method"`
	IsDefault      bool   `json:"is_default,omitempty"`
	VerificationID string `json:"verification_id,omitempty"`
}

func (s *Service) stepUpTwoFactorOptions(r *http.Request, userID string) *stepUpTwoFactorOptionsResponse {
	settings, err := s.svc.Get2FASettings(r.Context(), userID)
	if err != nil || settings == nil || !settings.Enabled {
		return nil
	}
	factors := settings.Factors
	if len(factors) == 0 && strings.TrimSpace(settings.Method) != "" {
		factors = []embedded.TwoFactorFactor{{
			Method:      strings.TrimSpace(settings.Method),
			PhoneNumber: settings.PhoneNumber,
			IsDefault:   true,
			Enabled:     true,
		}}
	}
	if len(factors) == 0 {
		return nil
	}

	emailDestination := ""
	var needsEmail bool
	for _, factor := range factors {
		if factor.Enabled && strings.EqualFold(factor.Method, "email") {
			needsEmail = true
			break
		}
	}
	if needsEmail {
		if user, err := s.svc.AdminGetUser(r.Context(), userID); err == nil && user != nil && user.Email != nil {
			emailDestination = *user.Email
		}
	}

	out := &stepUpTwoFactorOptionsResponse{}
	for _, factor := range factors {
		method := strings.ToLower(strings.TrimSpace(factor.Method))
		if !factor.Enabled || !validTwoFactorStepUpMethod(method) {
			continue
		}
		option := stepUpTwoFactorOptionResponse{
			Method:    method,
			IsDefault: factor.IsDefault,
		}
		switch method {
		case "email":
			if emailDestination != "" {
				option.VerificationID = obfuscateVerificationID(emailDestination)
			}
		case "sms":
			if factor.PhoneNumber != nil {
				option.VerificationID = obfuscateVerificationID(*factor.PhoneNumber)
			}
		}
		out.Methods = append(out.Methods, method)
		out.Options = append(out.Options, option)
		if factor.IsDefault {
			out.DefaultMethod = method
		}
	}
	if len(out.Methods) == 0 {
		return nil
	}
	if out.DefaultMethod == "" {
		out.DefaultMethod = out.Methods[0]
		out.Options[0].IsDefault = true
	}
	return out
}

func validTwoFactorStepUpMethod(method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "email", "sms", "totp":
		return true
	default:
		return false
	}
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

func obfuscateVerificationID(value string) string {
	if len(value) <= 5 {
		return value
	}
	return strings.Repeat("*", len(value)-5) + value[len(value)-5:]
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

func sanitizeStepUpReturnTo(value string) string {
	return sanitizeReturnTo(value)
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
