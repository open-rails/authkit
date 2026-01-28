package authhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	core "github.com/PaulFidika/authkit/core"
	oidckit "github.com/PaulFidika/authkit/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
)

func (s *Service) handleOIDCLoginGET(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLOIDCStart) {
		tooMany(w)
		return
	}

	provider := r.PathValue("provider")
	state := randB64(32)
	nonce := randB64(16)
	verifier, challenge, err := oidckit.GeneratePKCE()
	if err != nil {
		serverErr(w, "pkce_generation_failed")
		return
	}
	redirectURI := buildRedirectURI(r, provider)
	authURL, err := s.oidcCfg().Manager.Begin(r.Context(), provider, state, nonce, challenge, redirectURI)
	if err != nil {
		badRequest(w, "oidc_begin_failed")
		return
	}

	linkUserID := ""
	if r.URL.Query().Get("link") == "1" || strings.EqualFold(r.URL.Query().Get("link"), "true") {
		tokenStr := bearerToken(r.Header.Get("Authorization"))
		if tokenStr == "" {
			unauthorized(w, "auth_required_for_link")
			return
		}
		claims := jwt.MapClaims{}
		tok, err := jwt.ParseWithClaims(tokenStr, claims, s.svc.Keyfunc())
		if err != nil || tok == nil || !tok.Valid {
			unauthorized(w, "invalid_token")
			return
		}
		if sub, _ := claims["sub"].(string); sub != "" {
			linkUserID = sub
		} else {
			unauthorized(w, "invalid_token")
			return
		}
	}

	ui := r.URL.Query().Get("ui")
	if ui != "" && ui != "popup" {
		badRequest(w, "invalid_ui")
		return
	}
	popupNonce := r.URL.Query().Get("popup_nonce")

	if err := s.oidcCfg().StateCache.Put(r.Context(), state, oidckit.StateData{
		Provider:    provider,
		Verifier:    verifier,
		Nonce:       nonce,
		RedirectURI: redirectURI,
		LinkUserID:  linkUserID,
		UI:          ui,
		PopupNonce:  popupNonce,
	}); err != nil {
		serverErr(w, "state_store_failed")
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Service) handleOIDCCallbackGET(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLOIDCCallback) {
		tooMany(w)
		return
	}

	if qErr := r.URL.Query().Get("error"); qErr != "" {
		badRequest(w, qErr)
		return
	}

	provider := r.PathValue("provider")
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		badRequest(w, "invalid_request")
		return
	}

	cfg := s.oidcCfg()
	sd, ok, err := cfg.StateCache.Get(r.Context(), state)
	_ = cfg.StateCache.Del(r.Context(), state)
	if err != nil || !ok || sd.Provider != provider {
		badRequest(w, "invalid_state")
		return
	}

	rpClient, err := cfg.Manager.GetRPWithRedirect(r.Context(), provider, sd.RedirectURI)
	if err != nil {
		badRequest(w, "unknown_provider")
		return
	}
	issuer, ok := cfg.Manager.IssuerFor(provider)
	if !ok {
		badRequest(w, "unknown_provider")
		return
	}

	ex := oidckit.DefaultExchanger
	claims, err := ex(r.Context(), rpClient, provider, code, sd.Verifier, sd.Nonce)
	if err != nil {
		unauthorized(w, "oidc_exchange_failed")
		return
	}

	var userID, email string
	created := false
	if claims.Email != nil {
		email = *claims.Email
	}
	provUsername := ""
	if claims.PreferredUsername != nil {
		provUsername = *claims.PreferredUsername
	}

	if sd.LinkUserID != "" {
		if uid0, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), issuer, claims.Subject); err == nil && uid0 != "" && uid0 != sd.LinkUserID {
			sendErr(w, http.StatusConflict, "provider_already_linked")
			return
		}
		userID = sd.LinkUserID
		_ = s.svc.LinkProviderByIssuer(r.Context(), userID, issuer, provider, claims.Subject, claims.Email)
		if strings.TrimSpace(provUsername) != "" {
			_ = s.svc.SetProviderUsername(r.Context(), userID, issuer, claims.Subject, provUsername)
		}
	} else if uid, provEmail, err := s.svc.GetProviderLink(r.Context(), provider, claims.Subject); err == nil && uid != "" {
		userID = uid
		if email == "" && provEmail != nil {
			email = *provEmail
		}
		if strings.TrimSpace(provUsername) != "" {
			_ = s.svc.SetProviderUsername(r.Context(), userID, issuer, claims.Subject, provUsername)
		}
	} else {
		matched := false
		if claims.Email != nil && (claims.EmailVerified == nil || (claims.EmailVerified != nil && *claims.EmailVerified)) {
			if u, err := s.svc.GetUserByEmail(r.Context(), email); err == nil && u != nil {
				userID = u.ID
				matched = true
				_ = s.svc.LinkProviderByIssuer(r.Context(), u.ID, issuer, provider, claims.Subject, claims.Email)
				if claims.EmailVerified != nil && *claims.EmailVerified && provider != "discord" {
					_ = s.svc.SetEmailVerified(r.Context(), u.ID, true)
				}
				if strings.TrimSpace(provUsername) != "" {
					_ = s.svc.SetProviderUsername(r.Context(), userID, issuer, claims.Subject, provUsername)
				}
			}
		}
		if !matched {
			displayName := ""
			if claims.Name != nil {
				displayName = *claims.Name
			}
			username := s.svc.DeriveUsernameForOAuth(r.Context(), provider, provUsername, email, displayName)
			if u, err := s.svc.CreateUser(r.Context(), email, username); err == nil && u != nil {
				userID = u.ID
				if claims.EmailVerified != nil && *claims.EmailVerified && provider != "discord" {
					_ = s.svc.SetEmailVerified(r.Context(), u.ID, true)
				}
				_ = s.svc.LinkProviderByIssuer(r.Context(), u.ID, issuer, provider, claims.Subject, claims.Email)
				if strings.TrimSpace(provUsername) != "" {
					_ = s.svc.SetProviderUsername(r.Context(), u.ID, issuer, claims.Subject, provUsername)
				}
				created = true
			} else {
				serverErr(w, "user_creation_failed")
				return
			}
		}
	}

	extra := map[string]any{"provider": provider}
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
	token, exp, err := s.svc.IssueAccessToken(r.Context(), userID, email, extra)
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
	s.svc.LogSessionCreated(r.Context(), userID, "oidc_login", sid, ipPtr, uaPtr)

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
			"access_token":  token,
			"refresh_token": rt,
			"expires_in":    int64(time.Until(exp).Seconds()),
			"provider":      provider,
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
			"access_token":  token,
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
	frag := "#access_token=" + token + "&refresh_token=" + rt + "&expires_in=" + fmt.Sprint(int64(time.Until(exp).Seconds())) + "&provider=" + provider + "&state=" + state
	target := strings.TrimRight(base, "/") + "/auth/callback" + frag
	http.Redirect(w, r, target, http.StatusFound)
}

func buildPopupHTML(payloadJSON []byte, targetOrigin string) []byte {
	originJSON, _ := json.Marshal(targetOrigin)
	html := "<!doctype html><html><body><script>\n" +
		"try {\n" +
		"  var data = " + string(payloadJSON) + ";\n" +
		"  var targetOrigin = " + string(originJSON) + ";\n" +
		"  if (window.opener) { window.opener.postMessage(data, targetOrigin); }\n" +
		"} finally { /*window.close();*/ }\n" +
		"</script></body></html>"
	return []byte(html)
}
