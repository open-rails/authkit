package authhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	authkit "github.com/open-rails/authkit"
	"net/http"
	"net/url"
	"strings"
	"time"

	oidckit "github.com/open-rails/authkit/oidc"
)

func (s *Service) handleOIDCLoginGET(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if cfg, ok := s.oauth2Provider(provider); ok {
		s.handleOAuthLoginGET(w, r, cfg.Name)
		return
	}
	if r.URL.Query().Get("link") == "1" || strings.EqualFold(r.URL.Query().Get("link"), "true") {
		unauthorized(w, ErrAuthRequiredForLink)
		return
	}
	if s.rateLimited(w, r, RLOIDCStart) {
		return
	}

	state := randB64(32)
	nonce := randB64(16)
	verifier := ""
	challenge := ""
	manager := s.oidcManager()
	if pc, ok := manager.Provider(provider); ok && pc.PKCE {
		var err error
		verifier, challenge, err = oidckit.GeneratePKCE()
		if err != nil {
			serverErr(w, ErrPKCEGenerationFailed)
			return
		}
	}
	redirectURI := s.buildRedirectURI(r, provider)
	// AK F3: bind state to this browser (login CSRF defense).
	s.setStateCookie(w, r, state)
	authURL, err := manager.Begin(r.Context(), provider, state, nonce, challenge, redirectURI)
	if err != nil {
		badRequest(w, ErrOIDCBeginFailed)
		return
	}

	ui := r.URL.Query().Get("ui")
	if ui != "" && ui != "popup" {
		badRequest(w, ErrInvalidUI)
		return
	}
	popupNonce := r.URL.Query().Get("popup_nonce")

	if err := s.oidcCfg().StateCache.Put(r.Context(), state, oidckit.StateData{
		Provider:    provider,
		Verifier:    verifier,
		Nonce:       nonce,
		RedirectURI: redirectURI,
		ReturnTo:    sanitizeReturnTo(r.URL.Query().Get("return_to")),
		UI:          ui,
		PopupNonce:  popupNonce,
	}); err != nil {
		serverErr(w, ErrStateStoreFailed)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Service) handleOIDCCallbackGET(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if cfg, ok := s.oauth2Provider(provider); ok {
		s.handleOAuthCallbackGET(w, r, cfg.Name)
		return
	}
	if s.rateLimited(w, r, RLOIDCCallback) {
		return
	}

	if qErr := r.URL.Query().Get("error"); qErr != "" {
		badRequest(w, ErrorCode(qErr))
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}

	// AK F3: require the state cookie set at flow start (login CSRF defense).
	cookieOK := stateCookieMatches(r, state)
	clearStateCookie(w)
	if !cookieOK {
		badRequest(w, ErrInvalidState)
		return
	}

	cfg := s.oidcCfg()
	sd, ok, err := consumeState(r.Context(), cfg.StateCache, state)
	if err != nil || !ok || sd.Provider != provider {
		badRequest(w, ErrInvalidState)
		return
	}

	rpClient, err := cfg.Manager.GetRPWithRedirect(r.Context(), provider, sd.RedirectURI)
	if err != nil {
		badRequest(w, ErrUnknownProvider)
		return
	}
	issuer, ok := cfg.Manager.IssuerFor(provider)
	if !ok {
		badRequest(w, ErrUnknownProvider)
		return
	}

	ex := oidckit.DefaultExchanger
	claims, err := ex(r.Context(), rpClient, provider, code, sd.Verifier, sd.Nonce)
	if err != nil {
		unauthorized(w, ErrOIDCExchangeFailed)
		return
	}
	if s.completeOIDCStepUp(w, r, sd, provider, issuer, claims.Subject, claims.AuthTime) {
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
			sendErr(w, http.StatusConflict, ErrProviderAlreadyLinked)
			return
		}
		userID = sd.LinkUserID
		_ = s.svc.LinkProviderByIssuer(r.Context(), userID, issuer, provider, claims.Subject, claims.Email)
		if strings.TrimSpace(provUsername) != "" {
			_ = s.svc.SetProviderUsername(r.Context(), userID, issuer, claims.Subject, provUsername)
		}
	} else if uid, provEmail, err := s.svc.GetProviderLinkByIssuer(r.Context(), issuer, claims.Subject); err == nil && uid != "" {
		userID = uid
		if email == "" && provEmail != nil {
			email = *provEmail
		}
		if strings.TrimSpace(provUsername) != "" {
			_ = s.svc.SetProviderUsername(r.Context(), userID, issuer, claims.Subject, provUsername)
		}
	} else {
		// No (issuer, sub) link yet, and this is not an explicit link flow.
		//
		// SECURITY (C-2): never silently link a fresh IdP identity to a
		// pre-existing local account by matching its asserted email. An IdP that
		// asserts (or lies about) a victim's email — Apple private-relay, a
		// hostile/federated issuer, an organization-controlled mailbox — would otherwise
		// take over the victim's existing account with no proof the caller
		// controls it. If a local account already owns this email, refuse and
		// require the user to sign in and link the provider via the authenticated
		// /oidc/link/start flow.
		if strings.TrimSpace(email) != "" {
			if u, err := s.svc.GetUserByEmail(r.Context(), email); err == nil && u != nil {
				accountExistsLinkRequired(w)
				return
			}
		}

		// Brand-new identity with no existing local account: this is a public
		// registration path, blocked when public registration is disabled.
		if s.publicRegistrationDisabled() {
			registrationDisabled(w)
			return
		}
		displayName := ""
		if claims.Name != nil {
			displayName = *claims.Name
		}
		username := s.svc.DeriveUsernameForOAuth(r.Context(), provider, provUsername, email, displayName)
		u, err := s.svc.CreateUser(r.Context(), email, username)
		if err != nil || u == nil {
			serverErr(w, ErrUserCreationFailed)
			return
		}
		userID = u.ID
		// Trust the IdP's email_verified ONLY when it is explicitly true; an
		// absent claim is treated as false (defense in depth).
		if claims.EmailVerified != nil && *claims.EmailVerified && provider != "discord" {
			_ = s.svc.SetEmailVerified(r.Context(), u.ID, true)
		}
		_ = s.svc.LinkProviderByIssuer(r.Context(), u.ID, issuer, provider, claims.Subject, claims.Email)
		if strings.TrimSpace(provUsername) != "" {
			_ = s.svc.SetProviderUsername(r.Context(), u.ID, issuer, claims.Subject, provUsername)
		}
		created = true
	}

	extra := map[string]any{"provider": provider}
	sid, rt, _, err := s.svc.IssueRefreshSessionWithAuthMethods(r.Context(), userID, r.UserAgent(), nil, []string{"oauth"})
	if err != nil {
		if errors.Is(err, authkit.ErrTwoFAEnrollmentRequired) {
			s.write2FAEnrollmentRequired(w, r, userID)
			return
		}
		if errors.Is(err, authkit.ErrUserBanned) {
			unauthorized(w, ErrUserBanned)
			return
		}
		serverErr(w, ErrSessionIssueFailed)
		return
	}
	extra["sid"] = sid
	token, exp, err := s.svc.IssueAccessToken(r.Context(), userID, email, extra)
	if err != nil {
		if errors.Is(err, authkit.ErrUserBanned) {
			unauthorized(w, ErrUserBanned)
			return
		}
		serverErr(w, ErrTokenIssueFailed)
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
			serverErr(w, ErrInvalidBaseURL)
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
	frag := buildAuthResultFragment(token, rt, int64(time.Until(exp).Seconds()), provider, state, sd.ReturnTo)
	target := buildFrontendCallbackURL(base, s.svc.Options().FrontendCallbackPath, frag)
	http.Redirect(w, r, target, http.StatusFound)
}

// accountExistsLinkRequired is the C-2-safe outcome for an OIDC/OAuth2 callback
// whose (issuer, sub) is not yet linked but whose asserted email already belongs
// to a local account. We refuse to silently link the identity (that is the
// account-takeover vector) and signal that the user must sign in and link the
// provider explicitly via the authenticated /oidc/link/start flow. 409 Conflict
// with a stable machine-readable code so frontends can route to the link flow.
func accountExistsLinkRequired(w http.ResponseWriter) {
	sendErr(w, http.StatusConflict, ErrAccountExistsLinkRequired)
}

func buildFrontendCallbackURL(baseURL, callbackPath, fragment string) string {
	base := baseURL
	if base == "" {
		base = "/"
	}
	path := callbackPath
	if path == "" {
		path = "/login/callback"
	}
	return strings.TrimRight(base, "/") + path + fragment
}

func buildAuthResultFragment(accessToken, refreshToken string, expiresIn int64, provider, state, returnTo string) string {
	v := url.Values{}
	v.Set("access_token", accessToken)
	v.Set("refresh_token", refreshToken)
	v.Set("expires_in", fmt.Sprint(expiresIn))
	v.Set("provider", provider)
	v.Set("state", state)
	if rt := sanitizeReturnTo(returnTo); rt != "/" {
		v.Set("return_to", rt)
	}
	return "#" + v.Encode()
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
