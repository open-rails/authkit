package authhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/authprovider"
	core "github.com/open-rails/authkit/core"
	oidckit "github.com/open-rails/authkit/oidc"
)

var errProviderAlreadyLinked = errors.New("provider_already_linked")

func strptr(s string) *string {
	return &s
}

func (s *Service) handleOAuthLoginGET(w http.ResponseWriter, r *http.Request, provider string) {
	claimsUserID := ""
	if r.URL.Query().Get("link") == "1" || strings.EqualFold(r.URL.Query().Get("link"), "true") {
		unauthorized(w, "auth_required_for_link")
		return
	}
	s.startOAuthBrowserFlow(w, r, provider, claimsUserID, "", "")
}

func (s *Service) handleOAuthLinkStartPOST(w http.ResponseWriter, r *http.Request, provider string) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	s.startOAuthBrowserFlow(w, r, provider, claims.UserID, "", "")
}

func (s *Service) handleOAuthReauthStartPOST(w http.ResponseWriter, r *http.Request, provider string) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		unauthorized(w, "not_authenticated")
		return
	}
	var body struct {
		ReturnTo string `json:"return_to"`
	}
	_ = decodeJSON(r, &body)

	cfg, ok := s.oauth2Provider(provider)
	if !ok {
		badRequest(w, "unknown_provider")
		return
	}
	if !s.userHasLinkedIssuerProvider(r, claims.UserID, cfg.Issuer, cfg.Name) {
		badRequest(w, "provider_not_linked")
		return
	}
	s.startOAuthBrowserFlow(w, r, cfg.Name, "", claims.UserID, sanitizeReauthReturnTo(body.ReturnTo))
}

func (s *Service) startOAuthBrowserFlow(w http.ResponseWriter, r *http.Request, provider, linkUserID, reauthUserID, reauthReturnTo string) {
	cfg, ok := s.oauth2Provider(provider)
	if !ok {
		badRequest(w, "unknown_provider")
		return
	}
	if !s.allow(r, RLOIDCStart) {
		tooMany(w)
		return
	}
	rp, ok := s.oidcManager().Provider(cfg.Name)
	if !ok || strings.TrimSpace(rp.ClientID) == "" {
		badRequest(w, "unknown_provider")
		return
	}

	redirectURI := buildRedirectURI(r, cfg.Name)
	state := randB64(32)
	verifier := ""
	challenge := ""
	if cfg.PKCE {
		var err error
		verifier, challenge, err = oidckit.GeneratePKCE()
		if err != nil {
			serverErr(w, "pkce_generation_failed")
			return
		}
	}
	ui := r.URL.Query().Get("ui")
	if ui != "" && ui != "popup" {
		badRequest(w, "invalid_ui")
		return
	}
	popupNonce := r.URL.Query().Get("popup_nonce")
	sessionID := ""
	if strings.TrimSpace(reauthUserID) != "" {
		if claims, ok := ClaimsFromContext(r.Context()); ok {
			sessionID = claims.SessionID
		}
	}
	if err := s.stateCache().Put(r.Context(), state, oidckit.StateData{
		Provider:        cfg.Name,
		Verifier:        verifier,
		RedirectURI:     redirectURI,
		LinkUserID:      linkUserID,
		ReauthUserID:    reauthUserID,
		ReauthSessionID: sessionID,
		ReauthReturnTo:  reauthReturnTo,
		UI:              ui,
		PopupNonce:      popupNonce,
	}); err != nil {
		serverErr(w, "state_store_failed")
		return
	}

	scopes := cfg.Scopes
	if len(rp.Scopes) > 0 {
		scopes = rp.Scopes
	}
	q := url.Values{}
	q.Set("client_id", rp.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	if cfg.PKCE {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}
	authURL := cfg.AuthorizeURL + "?" + q.Encode()
	if strings.TrimSpace(linkUserID) != "" || strings.TrimSpace(reauthUserID) != "" || r.Method == http.MethodPost {
		writeJSON(w, http.StatusOK, map[string]any{"auth_url": authURL, "state": state})
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Service) handleOAuthCallbackGET(w http.ResponseWriter, r *http.Request, provider string) {
	cfg, ok := s.oauth2Provider(provider)
	if !ok {
		badRequest(w, "unknown_provider")
		return
	}
	if !s.allow(r, RLOIDCCallback) {
		tooMany(w)
		return
	}
	if qErr := r.URL.Query().Get("error"); qErr != "" {
		badRequest(w, qErr)
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		badRequest(w, "invalid_request")
		return
	}

	oidcCfg := s.oidcCfg()
	sd, ok, err := oidcCfg.StateCache.Get(r.Context(), state)
	_ = oidcCfg.StateCache.Del(r.Context(), state)
	if err != nil || !ok || sd.Provider != cfg.Name {
		badRequest(w, "invalid_state")
		return
	}

	rp, ok := oidcCfg.Manager.Provider(cfg.Name)
	if !ok || strings.TrimSpace(rp.ClientID) == "" || strings.TrimSpace(rp.ClientSecret) == "" {
		badRequest(w, "unknown_provider")
		return
	}
	token, err := s.exchangeOAuthCode(r, cfg, rp.ClientID, rp.ClientSecret, code, sd.RedirectURI, sd.Verifier)
	if err != nil {
		unauthorized(w, "exchange_failed")
		return
	}
	info, err := s.fetchOAuthUserInfo(r, cfg, token)
	if err != nil || strings.TrimSpace(info.Subject) == "" {
		unauthorized(w, "userinfo_failed")
		return
	}

	if s.completeOAuthReauth(w, r, sd, cfg, info.Subject) {
		return
	}

	userID, created, err := s.resolveOAuthUser(r, cfg, sd, info)
	if err != nil {
		if errors.Is(err, errProviderAlreadyLinked) {
			badRequest(w, "provider_already_linked")
			return
		}
		serverErr(w, "user_creation_failed")
		return
	}
	email := info.Email
	extra := map[string]any{"provider": cfg.Name}
	sid, rt, _, err := s.svc.IssueRefreshSession(r.Context(), userID, r.UserAgent(), nil)
	if err != nil {
		if errors.Is(err, core.ErrUserBanned) {
			unauthorized(w, "user_banned")
			return
		}
		serverErr(w, "session_issue_failed")
		return
	}
	extra["sid"] = sid
	accessToken, exp, err := s.svc.IssueAccessToken(r.Context(), userID, email, extra)
	if err != nil {
		if errors.Is(err, core.ErrUserBanned) {
			unauthorized(w, "user_banned")
			return
		}
		serverErr(w, "token_issue_failed")
		return
	}

	ua := r.UserAgent()
	ip := clientIP(r)
	uaPtr, ipPtr := &ua, &ip
	s.svc.LogSessionCreated(r.Context(), userID, "oauth_login:"+cfg.Name, sid, ipPtr, uaPtr)
	if created {
		s.svc.SendWelcome(r.Context(), userID)
	}

	if sd.UI == "popup" {
		targetOrigin, ok := originFromBaseURL(s.svc.Options().BaseURL)
		if !ok {
			serverErr(w, "invalid_base_url")
			return
		}
		payload := map[string]any{
			"type":          "AUTHKIT_OIDC_RESULT",
			"access_token":  accessToken,
			"refresh_token": rt,
			"expires_in":    int64(time.Until(exp).Seconds()),
			"provider":      cfg.Name,
			"nonce":         sd.PopupNonce,
		}
		b, _ := json.Marshal(payload)
		html := buildPopupHTML(b, targetOrigin)
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(html)
		return
	}

	if strings.EqualFold(r.URL.Query().Get("format"), "json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"expires_in":    int64(time.Until(exp).Seconds()),
			"refresh_token": rt,
			"user":          map[string]any{"id": userID, "email": email},
		})
		return
	}

	base := s.svc.Options().BaseURL
	if base == "" {
		base = "/"
	}
	frag := "#access_token=" + accessToken + "&refresh_token=" + rt + "&expires_in=" + fmt.Sprint(int64(time.Until(exp).Seconds())) + "&provider=" + cfg.Name + "&state=" + state
	target := buildFrontendCallbackURL(base, s.svc.Options().FrontendCallbackPath, frag)
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Service) exchangeOAuthCode(r *http.Request, cfg authprovider.Provider, clientID, clientSecret, code, redirectURI, verifier string) (oauth2TokenResp, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	if cfg.PKCE && strings.TrimSpace(verifier) != "" {
		form.Set("code_verifier", verifier)
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oauth2TokenResp{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.ReadAll(resp.Body)
		return oauth2TokenResp{}, errors.New("exchange_failed")
	}
	body, _ := io.ReadAll(resp.Body)
	var token oauth2TokenResp
	if json.Unmarshal(body, &token) != nil || strings.TrimSpace(token.AccessToken) == "" {
		return oauth2TokenResp{}, errors.New("exchange_failed")
	}
	if strings.TrimSpace(token.TokenType) == "" {
		token.TokenType = "Bearer"
	}
	return token, nil
}

func (s *Service) completeOAuthReauth(w http.ResponseWriter, r *http.Request, sd oidckit.StateData, cfg authprovider.Provider, subject string) bool {
	if strings.TrimSpace(sd.ReauthUserID) == "" {
		return false
	}
	userID, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), cfg.Issuer, subject)
	if err != nil || userID != sd.ReauthUserID {
		redirectReauthResult(w, r, sd.ReauthReturnTo, "failed")
		return true
	}
	if err := s.svc.MarkSessionAuthenticated(r.Context(), sd.ReauthUserID, sd.ReauthSessionID); err != nil {
		redirectReauthResult(w, r, sd.ReauthReturnTo, "failed")
		return true
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		freshness, _ := s.svc.SessionFreshness(r.Context(), sd.ReauthUserID, sd.ReauthSessionID, time.Now())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "fresh_auth": sessionFreshnessResponse(freshness), "provider": cfg.Name})
		return true
	}
	redirectReauthResult(w, r, sd.ReauthReturnTo, "success")
	return true
}

func (s *Service) resolveOAuthUser(r *http.Request, cfg authprovider.Provider, sd oidckit.StateData, info oauth2UserInfo) (string, bool, error) {
	emailPtr := strptr(info.Email)
	if sd.LinkUserID != "" {
		if uid0, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), cfg.Issuer, info.Subject); err == nil && uid0 != "" && uid0 != sd.LinkUserID {
			return "", false, errProviderAlreadyLinked
		}
		_ = s.svc.LinkProviderByIssuer(r.Context(), sd.LinkUserID, cfg.Issuer, cfg.Name, info.Subject, emailPtr)
		if strings.TrimSpace(info.Preferred) != "" {
			_ = s.svc.SetProviderUsername(r.Context(), sd.LinkUserID, cfg.Issuer, info.Subject, info.Preferred)
		}
		return sd.LinkUserID, false, nil
	}
	if uid, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), cfg.Issuer, info.Subject); err == nil && uid != "" {
		if strings.TrimSpace(info.Preferred) != "" {
			_ = s.svc.SetProviderUsername(r.Context(), uid, cfg.Issuer, info.Subject, info.Preferred)
		}
		return uid, false, nil
	}
	if info.EmailVerified && strings.TrimSpace(info.Email) != "" {
		if u, err := s.svc.GetUserByEmail(r.Context(), info.Email); err == nil && u != nil {
			_ = s.svc.LinkProviderByIssuer(r.Context(), u.ID, cfg.Issuer, cfg.Name, info.Subject, emailPtr)
			_ = s.svc.SetEmailVerified(r.Context(), u.ID, true)
			if strings.TrimSpace(info.Preferred) != "" {
				_ = s.svc.SetProviderUsername(r.Context(), u.ID, cfg.Issuer, info.Subject, info.Preferred)
			}
			return u.ID, false, nil
		}
	}
	username := s.svc.DeriveUsernameForOAuth(r.Context(), cfg.Name, info.Preferred, info.Email, info.Display)
	u, err := s.svc.CreateUser(r.Context(), info.Email, username)
	if err != nil || u == nil {
		return "", false, errors.New("user_creation_failed")
	}
	_ = s.svc.LinkProviderByIssuer(r.Context(), u.ID, cfg.Issuer, cfg.Name, info.Subject, emailPtr)
	if info.EmailVerified && strings.TrimSpace(info.Email) != "" {
		_ = s.svc.SetEmailVerified(r.Context(), u.ID, true)
	}
	if strings.TrimSpace(info.Preferred) != "" {
		_ = s.svc.SetProviderUsername(r.Context(), u.ID, cfg.Issuer, info.Subject, info.Preferred)
	}
	return u.ID, true, nil
}
