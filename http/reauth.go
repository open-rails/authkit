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
		FactorID   string `json:"factor_id"`
		BackupCode bool   `json:"backup_code"`
	}
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}

	if strings.TrimSpace(body.Code) == "" {
		destination, method, factor, err := s.svc.Require2FAForReauthFactor(r.Context(), claims.UserID, claims.SessionID, strings.TrimSpace(body.FactorID))
		if err != nil {
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
			"factor": twoFactorFactorResponse{
				ID:          factor.ID,
				Method:      factor.Method,
				IsDefault:   factor.IsDefault,
				PhoneNumber: factor.PhoneNumber,
			},
		})
		return
	}

	var valid bool
	var err error
	if body.BackupCode {
		valid, err = s.svc.VerifyBackupCode(r.Context(), claims.UserID, strings.TrimSpace(body.Code))
	} else {
		valid, err = s.svc.Verify2FAReauthFactorCode(r.Context(), claims.UserID, claims.SessionID, strings.TrimSpace(body.FactorID), strings.TrimSpace(body.Code))
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
	redirectURI := buildRedirectURI(r, provider)
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
	sendErrData(w, http.StatusForbidden, ErrReauthRequired, map[string]any{
		"reauth_methods":  s.reauthMethods(r, claims.UserID),
		"max_age_seconds": int64(core.SensitiveActionFreshAuthWindow.Seconds()),
	})
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

func sanitizeReauthReturnTo(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "/"
	}
	return value
}

func redirectReauthResult(w http.ResponseWriter, r *http.Request, returnTo, status string) {
	target := sanitizeReauthReturnTo(returnTo)
	u, err := url.Parse(target)
	if err != nil || u == nil {
		u = &url.URL{Path: "/"}
	}
	q := u.Query()
	q.Set("reauth", status)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
