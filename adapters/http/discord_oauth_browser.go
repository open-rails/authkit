package authhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	core "github.com/PaulFidika/authkit/core"
	oidckit "github.com/PaulFidika/authkit/oidc"
)

func (s *Service) handleDiscordLoginGET(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLOIDCStart) {
		tooMany(w)
		return
	}

	provider := "discord"

	scheme := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if host == "" {
		host = r.Host
	}
	path := r.URL.Path
	if strings.HasSuffix(path, "/login") {
		path = strings.TrimSuffix(path, "/login") + "/callback"
	} else {
		path = "/auth/oauth/discord/callback"
	}
	redirectURI := scheme + "://" + host + path

	st := randB64(24)
	ui := r.URL.Query().Get("ui")
	if ui != "" && ui != "popup" {
		badRequest(w, "invalid_ui")
		return
	}
	popupNonce := r.URL.Query().Get("popup_nonce")
	if err := s.oidcCfg().StateCache.Put(r.Context(), st, oidckit.StateData{Provider: provider, RedirectURI: redirectURI, UI: ui, PopupNonce: popupNonce}); err != nil {
		serverErr(w, "state_store_failed")
		return
	}

	q := url.Values{}
	rp, ok := s.oidcManager().Provider(provider)
	if !ok || strings.TrimSpace(rp.ClientID) == "" {
		badRequest(w, "unknown_provider")
		return
	}
	q.Set("client_id", rp.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	scopes := []string{"identify", "email"}
	if len(rp.Scopes) > 0 {
		scopes = rp.Scopes
	}
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", st)

	authorize := url.URL{Scheme: "https", Host: "discord.com", Path: "/api/oauth2/authorize", RawQuery: q.Encode()}
	http.Redirect(w, r, authorize.String(), http.StatusFound)
}

type discordTokenResp struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type discordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Global   string `json:"global_name"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

func (s *Service) handleDiscordCallbackGET(w http.ResponseWriter, r *http.Request) {
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

	cfg := s.oidcCfg()
	sd, ok, err := cfg.StateCache.Get(r.Context(), state)
	_ = cfg.StateCache.Del(r.Context(), state)
	if err != nil || !ok || sd.Provider != "discord" {
		badRequest(w, "invalid_state")
		return
	}

	rpCfg, ok := cfg.Manager.Provider("discord")
	if !ok || strings.TrimSpace(rpCfg.ClientID) == "" || strings.TrimSpace(rpCfg.ClientSecret) == "" {
		badRequest(w, "unknown_provider")
		return
	}

	form := url.Values{}
	form.Set("client_id", rpCfg.ClientID)
	form.Set("client_secret", rpCfg.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", sd.RedirectURI)
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://discord.com/api/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		unauthorized(w, "exchange_failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		_, _ = io.ReadAll(resp.Body)
		unauthorized(w, "exchange_failed")
		return
	}
	body, _ := io.ReadAll(resp.Body)
	var tok discordTokenResp
	if json.Unmarshal(body, &tok) != nil || strings.TrimSpace(tok.AccessToken) == "" {
		unauthorized(w, "exchange_failed")
		return
	}

	ureq, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://discord.com/api/users/@me", nil)
	ureq.Header.Set("Authorization", tok.TokenType+" "+tok.AccessToken)
	uresp, err := http.DefaultClient.Do(ureq)
	if err != nil {
		unauthorized(w, "userinfo_failed")
		return
	}
	defer uresp.Body.Close()
	if uresp.StatusCode != 200 {
		unauthorized(w, "userinfo_failed")
		return
	}
	ubody, _ := io.ReadAll(uresp.Body)
	var du discordUser
	if json.Unmarshal(ubody, &du) != nil || strings.TrimSpace(du.ID) == "" {
		unauthorized(w, "userinfo_failed")
		return
	}

	email := ""
	if du.Verified && strings.TrimSpace(du.Email) != "" {
		email = strings.TrimSpace(du.Email)
	}
	preferred := du.Username
	display := du.Global

	const issuer = "https://discord.com"
	var userID string
	created := false

	if sd.LinkUserID != "" {
		if uid0, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), issuer, du.ID); err == nil && uid0 != "" && uid0 != sd.LinkUserID {
			badRequest(w, "provider_already_linked")
			return
		}
		userID = sd.LinkUserID
		_ = s.svc.LinkProviderByIssuer(r.Context(), userID, issuer, "discord", du.ID, strptr(email))
		if strings.TrimSpace(preferred) != "" {
			_ = s.svc.SetProviderUsername(r.Context(), userID, issuer, du.ID, preferred)
		}
	} else if uid, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), issuer, du.ID); err == nil && uid != "" {
		userID = uid
	} else if email != "" {
		if u, err := s.svc.GetUserByEmail(r.Context(), email); err == nil && u != nil {
			userID = u.ID
			_ = s.svc.LinkProviderByIssuer(r.Context(), u.ID, issuer, "discord", du.ID, strptr(email))
			_ = s.svc.SetEmailVerified(r.Context(), u.ID, true)
			_ = s.svc.SetProviderUsername(r.Context(), u.ID, issuer, du.ID, preferred)
		}
	}
	if userID == "" {
		username := s.svc.DeriveUsernameForOAuth(r.Context(), "discord", preferred, email, display)
		if u, err := s.svc.CreateUser(r.Context(), email, username); err == nil && u != nil {
			userID = u.ID
			_ = s.svc.LinkProviderByIssuer(r.Context(), u.ID, issuer, "discord", du.ID, strptr(email))
			if email != "" {
				_ = s.svc.SetEmailVerified(r.Context(), u.ID, true)
			}
			_ = s.svc.SetProviderUsername(r.Context(), u.ID, issuer, du.ID, preferred)
			created = true
		} else {
			serverErr(w, "user_creation_failed")
			return
		}
	}

	extra := map[string]any{"provider": "discord"}
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
	s.svc.LogSessionCreated(r.Context(), userID, "oauth_login:discord", sid, ipPtr, uaPtr)
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
			"provider":      "discord",
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
	frag := "#access_token=" + accessToken + "&refresh_token=" + rt + "&expires_in=" + fmt.Sprint(int64(time.Until(exp).Seconds())) + "&provider=discord&state=" + state
	target := strings.TrimRight(base, "/") + "/auth/callback" + frag
	http.Redirect(w, r, target, http.StatusFound)
}

func strptr(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	v := s
	return &v
}

var _ = context.Background
