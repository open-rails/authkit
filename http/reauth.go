package authhttp

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
	"github.com/open-rails/authkit/internal/db"
	oidckit "github.com/open-rails/authkit/oidc"
)

const oidcReauthClockSkew = 2 * time.Minute

func ptr(s string) *string { return &s }

func (s *Service) handlePasswordReauthPOST(w http.ResponseWriter, r *http.Request) {
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
		if errors.Is(verr, core.ErrPasswordResetRequired) {
			// The stored hash can never verify (legacy reset-required); the user
			// cannot reauth with a password and must reset it first.
			unauthorized(w, ErrPasswordResetRequired)
			return
		}
		unauthorized(w, ErrInvalidPassword)
		return
	}
	if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
		serverErr(w, ErrReauthFailed)
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

func (s *Service) handleTwoFactorReauthPOST(w http.ResponseWriter, r *http.Request) {
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
	if method != "" && !validTwoFactorReauthMethod(method) {
		badRequest(w, ErrInvalidMethod)
		return
	}

	if strings.TrimSpace(body.Code) == "" {
		destination, method, _, err := s.svc.Require2FAForReauthMethod(r.Context(), claims.UserID, claims.SessionID, method)
		if err != nil {
			if method != "" {
				badRequest(w, ErrInvalidMethod)
				return
			}
			if s.handleDeliveryError(w, r, "reauth_2fa", "send_2fa_code", err) {
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
		valid, err = s.svc.Verify2FAReauthMethodCode(r.Context(), claims.UserID, claims.SessionID, method, strings.TrimSpace(body.Code))
	}
	if err != nil || !valid {
		unauthorized(w, ErrInvalidCode)
		return
	}

	methods := []string{"otp", "mfa"}
	if freshness, err := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now()); err == nil {
		methods = append(freshness.AuthMethods, methods...)
	}
	if err := s.svc.MarkSessionAuthenticatedWithMethods(r.Context(), claims.UserID, claims.SessionID, methods); err != nil {
		serverErr(w, ErrReauthFailed)
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

func (s *Service) handleOIDCReauthStartPOST(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.PathValue("provider"))
	if cfg, ok := s.oauth2Provider(provider); ok {
		s.handleOAuthReauthStartPOST(w, r, cfg.Name)
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
		ReauthUserID:    claims.UserID,
		ReauthSessionID: claims.SessionID,
		ReauthReturnTo:  sanitizeReauthReturnTo(body.ReturnTo),
		ReauthStartedAt: startedAt,
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

func (s *Service) completeOIDCReauth(w http.ResponseWriter, r *http.Request, sd oidckit.StateData, provider, issuer, subject string, authTime time.Time) bool {
	if strings.TrimSpace(sd.ReauthUserID) == "" {
		return false
	}
	userID, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), issuer, subject)
	if err != nil || userID != sd.ReauthUserID {
		redirectReauthResult(w, r, sd.ReauthReturnTo, "failed")
		return true
	}
	if !validOIDCReauthTime(sd.ReauthStartedAt, authTime, time.Now().UTC()) {
		redirectReauthResult(w, r, sd.ReauthReturnTo, "failed")
		return true
	}
	if err := s.svc.MarkSessionAuthenticated(r.Context(), sd.ReauthUserID, sd.ReauthSessionID); err != nil {
		redirectReauthResult(w, r, sd.ReauthReturnTo, "failed")
		return true
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		freshness, _ := s.svc.SessionFreshness(r.Context(), sd.ReauthUserID, sd.ReauthSessionID, time.Now())
		body, err := s.freshAccessTokenResponse(r, sd.ReauthUserID, sd.ReauthSessionID, freshness)
		if err != nil {
			redirectReauthResult(w, r, sd.ReauthReturnTo, "failed")
			return true
		}
		body["provider"] = provider
		writeJSON(w, http.StatusOK, body)
		return true
	}
	redirectReauthResult(w, r, sd.ReauthReturnTo, "success")
	return true
}

func validOIDCReauthTime(startedAt, authTime, now time.Time) bool {
	if startedAt.IsZero() || authTime.IsZero() || authTime.After(now.Add(oidcReauthClockSkew)) {
		return false
	}
	return !authTime.Before(startedAt.Add(-oidcReauthClockSkew))
}

func (s *Service) requireFreshAuthOrPassword(w http.ResponseWriter, r *http.Request, claims Claims, password string) (bool, map[string]any) {
	if SensitiveClaims(claims) {
		return true, nil
	}
	if password != "" {
		if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, password); verr != nil {
			if errors.Is(verr, core.ErrPasswordResetRequired) {
				unauthorized(w, ErrPasswordResetRequired)
				return false, nil
			}
			unauthorized(w, ErrInvalidPassword)
			return false, nil
		}
		if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
			serverErr(w, ErrReauthFailed)
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
	s.reauthRequired(w, r, claims)
	return false, nil
}

func (s *Service) reauthRequired(w http.ResponseWriter, r *http.Request, claims Claims) {
	metadata := map[string]any{
		"reauth_methods":  s.reauthMethods(r, claims.UserID),
		"max_age_seconds": int64(core.SensitiveActionFreshAuthWindow.Seconds()),
	}
	if twoFA := s.reauthTwoFactorOptions(r, claims.UserID); twoFA != nil {
		metadata["reauth_2fa"] = twoFA
	}
	sendErrData(w, http.StatusForbidden, ErrReauthRequired, metadata)
}

func (s *Service) freshAccessTokenResponse(r *http.Request, userID, sessionID string, freshness core.SessionFreshness) (map[string]any, error) {
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

func (s *Service) reauthMethods(r *http.Request, userID string) []string {
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

type reauthTwoFactorOptionsResponse struct {
	Methods       []string                        `json:"methods,omitempty"`
	DefaultMethod string                          `json:"default_method,omitempty"`
	Options       []reauthTwoFactorOptionResponse `json:"options,omitempty"`
}

type reauthTwoFactorOptionResponse struct {
	Method         string `json:"method"`
	IsDefault      bool   `json:"is_default,omitempty"`
	VerificationID string `json:"verification_id,omitempty"`
}

func (s *Service) reauthTwoFactorOptions(r *http.Request, userID string) *reauthTwoFactorOptionsResponse {
	settings, err := s.svc.Get2FASettings(r.Context(), userID)
	if err != nil || settings == nil || !settings.Enabled {
		return nil
	}
	factors := settings.Factors
	if len(factors) == 0 && strings.TrimSpace(settings.Method) != "" {
		factors = []core.TwoFactorFactor{{
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

	out := &reauthTwoFactorOptionsResponse{}
	for _, factor := range factors {
		method := strings.ToLower(strings.TrimSpace(factor.Method))
		if !factor.Enabled || !validTwoFactorReauthMethod(method) {
			continue
		}
		option := reauthTwoFactorOptionResponse{
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

func validTwoFactorReauthMethod(method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "email", "sms", "totp":
		return true
	default:
		return false
	}
}

func sessionFreshnessResponse(f core.SessionFreshness) map[string]any {
	out := map[string]any{
		"reauth_required_for_sensitive_actions": f.ReauthRequiredForSensitiveOps,
		"time_until_reauth_required":            int64((f.TimeUntilReauthRequired + time.Second - time.Nanosecond) / time.Second),
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

func sanitizeReauthReturnTo(value string) string {
	return sanitizeReturnTo(value)
}

func redirectReauthResult(w http.ResponseWriter, r *http.Request, returnTo, status string) {
	target := sanitizeReturnTo(returnTo)
	u, err := url.Parse(target)
	if err != nil || u == nil {
		u = &url.URL{Path: "/"}
	}
	q := u.Query()
	q.Set("reauth", status)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
