package authhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	authkit "github.com/open-rails/authkit"
	stdlog "log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/oidckit"
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
		Provider:           provider,
		Verifier:           verifier,
		Nonce:              nonce,
		RedirectURI:        redirectURI,
		ReturnTo:           sanitizeReturnTo(r.URL.Query().Get("return_to")),
		AccountInviteToken: strings.TrimSpace(r.URL.Query().Get("account_invite_token")),
		UI:                 ui,
		PopupNonce:         popupNonce,
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
		// The provider link is the load-bearing write: if it fails we must NOT report
		// success, or the next login won't find the link and will diverge (duplicate
		// account / link-required dead-end). Fail the callback (#176 Part B — this error
		// was previously swallowed; failing closed matches the OAuth2 path).
		if err := s.svc.LinkProviderByIssuer(r.Context(), userID, issuer, provider, claims.Subject, claims.Email); err != nil {
			stdlog.Printf("[authkit/security] error: provider link write failed (user=%s issuer=%s); failing OIDC callback: %v", userID, issuer, err)
			serverErr(w, ErrProviderLinkFailed)
			return
		}
		if strings.TrimSpace(provUsername) != "" {
			// Cosmetic write: never fail the callback, but never swallow silently
			// either (#199 — matches the OAuth2 sibling's treatment).
			if err := s.svc.SetProviderUsername(r.Context(), userID, issuer, claims.Subject, provUsername); err != nil {
				stdlog.Printf("[authkit/security] warning: SetProviderUsername failed (user=%s issuer=%s); link succeeded, username not updated: %v", userID, issuer, err)
			}
		}
	} else if uid, provEmail, err := s.svc.GetProviderLinkByIssuer(r.Context(), issuer, claims.Subject); err == nil && uid != "" {
		userID = uid
		if email == "" && provEmail != nil {
			email = *provEmail
		}
		if strings.TrimSpace(provUsername) != "" {
			if err := s.svc.SetProviderUsername(r.Context(), userID, issuer, claims.Subject, provUsername); err != nil {
				stdlog.Printf("[authkit/security] warning: SetProviderUsername failed (user=%s issuer=%s); login succeeded, username not updated: %v", userID, issuer, err)
			}
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
		// registration path. InviteOnly requires an unbound account invite token
		// carried from flow start; Open keeps the historical behavior.
		if s.svc.Config().Registration.NativeUserMode == embedded.RegistrationModeInviteOnly {
			if strings.TrimSpace(email) == "" {
				registrationDisabled(w)
				return
			}
			allowed, err := s.svc.RegistrationAllowedForEmailWithInvite(r.Context(), email, sd.AccountInviteToken)
			if err != nil {
				serverErr(w, ErrDatabaseError)
				return
			}
			if !allowed {
				registrationDisabled(w)
				return
			}
		} else if s.publicRegistrationDisabled() {
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
			if err := s.svc.SetEmailVerified(r.Context(), u.ID, true); err != nil {
				stdlog.Printf("[authkit/security] warning: SetEmailVerified failed for new user %s (recoverable; user+link created): %v", u.ID, err)
			}
		}
		if err := s.svc.ConsumeAccountRegistrationInvite(r.Context(), email, u.ID, sd.AccountInviteToken); err != nil {
			serverErr(w, ErrUserCreationFailed)
			return
		}
		// Load-bearing link write (see explicit-link branch above): fail closed rather
		// than leave the just-created user unlinked while reporting success (#176 Part B).
		// NOTE: without a create+link transaction this leaves an orphan user row on
		// failure (logged CRITICAL); atomic create+link is the proper follow-up.
		if err := s.svc.LinkProviderByIssuer(r.Context(), u.ID, issuer, provider, claims.Subject, claims.Email); err != nil {
			stdlog.Printf("[authkit/security] CRITICAL: provider link write failed after user creation (orphan user=%s issuer=%s subject=%s); failing OIDC callback — manual cleanup may be required: %v", u.ID, issuer, claims.Subject, err)
			serverErr(w, ErrProviderLinkFailed)
			return
		}
		if strings.TrimSpace(provUsername) != "" {
			if err := s.svc.SetProviderUsername(r.Context(), u.ID, issuer, claims.Subject, provUsername); err != nil {
				stdlog.Printf("[authkit/security] warning: SetProviderUsername failed for new user %s (cosmetic): %v", u.ID, err)
			}
		}
		created = true
	}

	s.finishBrowserLogin(w, r, userID, email, provider, "oidc_login", created, sd)
}

// finishBrowserLogin is the shared post-resolve tail of the OIDC and OAuth2 browser
// callbacks (#176 Part A): issue session + access token (with the same 2FA-enrollment
// / banned / failure handling), log the session, send a welcome on first creation,
// and emit the result as a popup postMessage, a JSON body, or a fragment redirect.
// providerName and sessionEvent are the only per-flow parameters.
func (s *Service) finishBrowserLogin(w http.ResponseWriter, r *http.Request, userID, email, providerName, sessionEvent string, created bool, sd oidckit.StateData) {
	extra := map[string]any{"provider": providerName}
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
	token, exp, err := s.svc.MintAccessToken(r.Context(), userID, extra)
	if err != nil {
		if errors.Is(err, authkit.ErrUserBanned) {
			unauthorized(w, ErrUserBanned)
			return
		}
		serverErr(w, ErrTokenIssueFailed)
		return
	}

	ua := r.UserAgent()
	ip := remoteIP(r)
	uaPtr, ipPtr := &ua, &ip
	s.svc.LogSessionCreated(r.Context(), userID, sessionEvent, sid, ipPtr, uaPtr)

	if created {
		s.svc.SendWelcome(r.Context(), userID)
	}

	if sd.UI == "popup" {
		targetOrigin, ok := originFromBaseURL(s.svc.Config().Frontend.BaseURL)
		if !ok {
			serverErr(w, ErrInvalidBaseURL)
			return
		}
		payload := map[string]any{
			"type":          "AUTHKIT_OIDC_RESULT",
			"access_token":  token,
			"refresh_token": rt,
			"expires_in":    int64(time.Until(exp).Seconds()),
			"provider":      providerName,
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
		writeAccessTokenJSON(w, http.StatusOK, newAuthTokens(token, rt, exp), map[string]any{
			"user": map[string]any{"id": userID, "email": email},
		})
		return
	}

	base := s.svc.Config().Frontend.BaseURL
	if base == "" {
		base = "/"
	}
	state := r.URL.Query().Get("state")
	frag := buildAuthResultFragment(token, rt, int64(time.Until(exp).Seconds()), providerName, state, sd.ReturnTo)
	target := buildFrontendCallbackURL(base, s.svc.Config().Frontend.OIDCReturnPath, frag)
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
