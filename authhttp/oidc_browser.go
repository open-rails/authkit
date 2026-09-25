package authhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/oidckit"
	"github.com/open-rails/authkit/verify"
)

// flowStart is what a browser flow start records beyond the state machine's
// own state/nonce/PKCE values.
type flowStart struct {
	link   *embedded.ExternalLinkAuthorization
	stepUp *oidckit.StateData // StepUp* fields to carry
	params map[string]string  // extra authorization parameters
	login  *loginStart
}

// loginStart is a plain login's browser context.
type loginStart struct {
	ui, popupNonce, returnTo, accountInviteToken string
}

func (s *Service) handleOIDCLoginGET(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	q := r.URL.Query()
	if q.Get("link") == "1" || strings.EqualFold(q.Get("link"), "true") {
		s.failBrowserFlow(w, r, nil, provider, http.StatusUnauthorized, authkit.CodeAuthRequiredForLink)
		return
	}
	// An invitation is a bearer credential: it never rides in a URL, where
	// history, logs and Referer keep it. POST /{provider}/login binds it to the
	// flow's server-side state instead.
	if q.Has("account_invite_token") {
		s.failBrowserFlow(w, r, nil, provider, http.StatusBadRequest, authkit.CodeInvalidRequest)
		return
	}
	s.startProviderFlow(w, r, provider, flowStart{login: &loginStart{ui: q.Get("ui"), popupNonce: q.Get("popup_nonce"), returnTo: q.Get("return_to")}})
}

// handleOIDCLoginPOST starts a login from the page's own origin and answers
// {"auth_url","state"}; the page then navigates (or its popup does) to
// auth_url. It is the only start that accepts an account invitation.
func (s *Service) handleOIDCLoginPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReturnTo           string `json:"return_to"`
		AccountInviteToken string `json:"account_invite_token"`
		UI                 string `json:"ui"`
		PopupNonce         string `json:"popup_nonce"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	// The response sets the flow's state cookie; a cross-site page must not
	// bind a flow into this browser.
	if !s.cookieOriginAllowed(r) {
		forbidden(w, authkit.CodeForbidden)
		return
	}
	s.startProviderFlow(w, r, r.PathValue("provider"), flowStart{login: &loginStart{
		ui: req.UI, popupNonce: req.PopupNonce, returnTo: req.ReturnTo, accountInviteToken: req.AccountInviteToken,
	}})
}

func (s *Service) handleOIDCLinkStartPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	if !s.requireProvenContact(w, r, claims.UserID) {
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}
	freshness, err := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
	if err != nil || freshness.StepUpRequiredForSensitiveOps {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	s.startProviderFlow(w, r, r.PathValue("provider"), flowStart{link: &embedded.ExternalLinkAuthorization{UserID: claims.UserID, SessionID: claims.SessionID, AuthenticatedAt: freshness.LastAuthenticatedAt}})
}

// startProviderFlow begins a login, link or step-up flow: it generates state,
// nonce and (when the provider uses it) PKCE, binds state to this browser,
// stores the pending flow, and sends the browser to the provider. A plain GET
// login is a browser navigation and is redirected; link and step-up starts
// (and any POST) are fetch calls and receive {"auth_url","state"} JSON.
func (s *Service) startProviderFlow(w http.ResponseWriter, r *http.Request, name string, start flowStart) {
	browserNav := start.login != nil && r.Method != http.MethodPost
	fail := func(status int, code authkit.Code) {
		if browserNav {
			s.failBrowserFlow(w, r, nil, name, status, code)
			return
		}
		sendErr(w, status, code)
	}
	p, ok := s.provider(name)
	if !ok {
		fail(http.StatusBadRequest, authkit.CodeUnknownProvider)
		return
	}
	if s.rateLimited(w, r, RLOIDCStart) {
		return
	}
	var login loginStart
	if start.login != nil {
		login = *start.login
		if login.ui != "" && login.ui != "popup" {
			fail(http.StatusBadRequest, authkit.CodeInvalidUI)
			return
		}
	}

	state := embedded.RandB64(32)
	nonce := embedded.RandB64(16)
	verifier, challenge := "", ""
	if p.PKCE() {
		var err error
		if verifier, challenge, err = oidckit.GeneratePKCE(); err != nil {
			fail(http.StatusInternalServerError, authkit.CodePKCEGenerationFailed)
			return
		}
	}
	redirectURI := s.buildRedirectURI(r, p.Name())
	// AK F3: bind state to this browser so a third party can't drive a victim
	// through the callback with an attacker-issued state+code (login CSRF).
	s.setStateCookie(w, r, p, state)
	authURL, err := p.AuthCodeURL(r.Context(), authprovider.AuthRequest{
		State: state, Nonce: nonce, CodeChallenge: challenge, RedirectURI: redirectURI, Params: start.params,
	})
	if errors.Is(err, authprovider.ErrProviderUnavailable) {
		fail(http.StatusServiceUnavailable, authkit.CodeProviderUnavailable)
		return
	}
	if err != nil {
		fail(http.StatusBadRequest, authkit.CodeOIDCBeginFailed)
		return
	}
	sd := oidckit.StateData{
		Provider:    p.Name(),
		Verifier:    verifier,
		Nonce:       nonce,
		RedirectURI: redirectURI,
		UI:          login.ui,
		PopupNonce:  login.popupNonce,
	}
	if start.link != nil {
		sd.LinkUserID = start.link.UserID
		sd.LinkSessionID = start.link.SessionID
		sd.LinkAuthenticatedAt = start.link.AuthenticatedAt
	}
	if start.login != nil {
		sd.ReturnTo = sanitizeReturnTo(login.returnTo)
		sd.AccountInviteToken = strings.TrimSpace(login.accountInviteToken)
	}
	if start.stepUp != nil {
		sd.StepUpUserID = start.stepUp.StepUpUserID
		sd.StepUpSessionID = start.stepUp.StepUpSessionID
		sd.StepUpReturnTo = start.stepUp.StepUpReturnTo
		sd.StepUpStartedAt = start.stepUp.StepUpStartedAt
	}
	if err := s.svc.PutOIDCState(r.Context(), state, sd); err != nil {
		fail(http.StatusInternalServerError, authkit.CodeStateStoreFailed)
		return
	}
	if browserNav {
		http.Redirect(w, r, authURL, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"auth_url": authURL, "state": state})
}

// handleOIDCCallbackGET completes the browser flow for the IdP's GET redirect
// and, for response_mode=form_post providers, the equivalent POST (#295).
func (s *Service) handleOIDCCallbackGET(w http.ResponseWriter, r *http.Request) {
	// Every callback response carries the flow result (tokens, error, popup
	// document); none may be cached.
	w.Header().Set("Cache-Control", "no-store")
	name := r.PathValue("provider")
	p, ok := s.provider(name)
	if !ok {
		s.failBrowserFlow(w, r, nil, name, http.StatusBadRequest, authkit.CodeUnknownProvider)
		return
	}
	name = p.Name()
	// The IdP echoes state on error redirects too; recover the flow context
	// when this browser really started the flow, so the error lands where the
	// flow expects it (popup message / step-up return / frontend fragment).
	params := callbackParams(r)
	if qErr := params.Get("error"); qErr != "" {
		logIdPCallbackError(name, r)
		errSD := s.recoverCallbackState(w, r, p)
		s.failBrowserFlow(w, r, errSD, name, http.StatusBadRequest, sanitizeProviderErrorCode(qErr))
		return
	}
	state := params.Get("state")
	code := params.Get("code")
	if state == "" || code == "" {
		s.failBrowserFlow(w, r, nil, name, http.StatusBadRequest, authkit.CodeInvalidRequest)
		return
	}

	// AK F3: the browser completing the callback must present the state cookie
	// set at flow start. This blocks login CSRF, where an attacker supplies a
	// valid state+code captured from their own login.
	cookieOK := s.stateCookieMatches(r, p, state)
	s.clearStateCookie(w, r, p, state)
	if !cookieOK {
		s.failBrowserFlow(w, r, nil, name, http.StatusBadRequest, authkit.CodeInvalidState)
		return
	}
	sd, ok, err := s.svc.ConsumeOIDCState(r.Context(), state)
	if err != nil || !ok || sd.Provider != name {
		s.failBrowserFlow(w, r, nil, name, http.StatusBadRequest, authkit.CodeInvalidState)
		return
	}

	identity, err := p.Exchange(r.Context(), authprovider.ExchangeRequest{
		Code: code, CodeVerifier: sd.Verifier, Nonce: sd.Nonce, RedirectURI: sd.RedirectURI,
	})
	if errors.Is(err, authprovider.ErrProviderUnavailable) {
		s.failBrowserFlow(w, r, &sd, name, http.StatusServiceUnavailable, authkit.CodeProviderUnavailable)
		return
	}
	if err != nil || strings.TrimSpace(identity.Subject) == "" {
		s.failBrowserFlow(w, r, &sd, name, http.StatusUnauthorized, authkit.CodeOIDCExchangeFailed)
		return
	}
	if s.completeOIDCStepUp(w, r, sd, name, p.Issuer(), identity.Subject, identity.AuthTime) {
		return
	}

	var link *embedded.ExternalLinkAuthorization
	if sd.LinkUserID != "" {
		link = &embedded.ExternalLinkAuthorization{UserID: sd.LinkUserID, SessionID: sd.LinkSessionID, AuthenticatedAt: sd.LinkAuthenticatedAt}
	}
	out, err := s.svc.CompleteExternalLogin(r.Context(), embedded.ExternalLoginInput{
		Identity: embedded.ExternalIdentity{
			Provider: name, Issuer: p.Issuer(), Subject: identity.Subject,
			Email: identity.Email, EmailVerified: identity.EmailVerified && p.TrustsEmailVerification(),
			PreferredUsername: identity.PreferredUsername, DisplayName: identity.DisplayName,
		},
		Link: link, AccountInviteToken: sd.AccountInviteToken,
		Event: "oidc_login", UserAgent: r.UserAgent(), IP: s.requestIP(r),
	})
	if err != nil {
		status, code := wireCode(err)
		s.failBrowserFlow(w, r, &sd, name, status, code)
		return
	}
	if out.Kind == embedded.LoginProviderLinked {
		if wantsJSONResponse(r) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		fragment := url.Values{"flow": {"link"}, "result": {"success"}, "provider": {name}}
		target := buildFrontendCallbackURL(s.svc.Config().Frontend.BaseURL, s.svc.Config().Frontend.OIDCReturnPath, "#"+fragment.Encode())
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	if out.Kind != embedded.LoginSessionIssued {
		s.browserLoginContinuation(w, r, out, name, sd)
		return
	}
	s.emitBrowserLogin(w, r, out.UserID, name, *out.Session, sd)
}

// emitBrowserLogin hands the browser its session as a popup postMessage, a
// JSON body, or a fragment redirect — the transport half of the callback.
func (s *Service) emitBrowserLogin(w http.ResponseWriter, r *http.Request, userID, providerName string, session embedded.IssuedSession, sd oidckit.StateData) {
	token, rt, exp := session.AccessToken, session.RefreshToken, session.AccessExpiresAt
	// ak#271: the popup document and the fragment redirect both hand the
	// browser its tokens in script-readable form by design. The ACCESS token
	// has to stay there — it is short-lived and the SPA builds the
	// Authorization header from it — but the durable refresh token moves to
	// the cookie, which these same-origin responses can set.
	if sd.UI == "popup" {
		targetOrigin, ok := originFromBaseURL(s.svc.Config().Frontend.BaseURL)
		if !ok {
			s.failBrowserFlow(w, r, &sd, providerName, http.StatusInternalServerError, authkit.CodeInvalidBaseURL)
			return
		}
		deliveredRT := s.deliverRefreshToken(w, r, authkit.NewTokenSet(token, rt, exp)).RefreshToken
		payload := map[string]any{
			"type":         "AUTHKIT_OIDC_RESULT",
			"access_token": token,
			"expires_in":   int64(time.Until(exp).Seconds()),
			"provider":     providerName,
			"nonce":        sd.PopupNonce,
		}
		if deliveredRT != "" {
			payload["refresh_token"] = deliveredRT
		}
		b, _ := json.Marshal(payload)
		writePopupDocument(w, buildPopupHTML(b, targetOrigin))
		return
	}

	if wantsJSONResponse(r) {
		// Provider email is descriptive metadata; return the account's own
		// nullable address, including on an explicit provider-link callback.
		user, err := s.svc.AdminGetUser(r.Context(), userID)
		if err != nil || user == nil {
			s.failBrowserFlow(w, r, &sd, providerName, http.StatusInternalServerError, authkit.CodeUserLookupFailed)
			return
		}
		s.writeTokenSetWith(w, r, http.StatusOK, authkit.NewTokenSet(token, rt, exp), map[string]any{
			"user": map[string]any{"id": userID, "email": user.Email},
		})
		return
	}

	base := s.svc.Config().Frontend.BaseURL
	if base == "" {
		base = "/"
	}
	state := callbackParams(r).Get("state")
	fragmentRT := s.deliverRefreshToken(w, r, authkit.NewTokenSet(token, rt, exp)).RefreshToken
	frag := buildAuthResultFragment(token, fragmentRT, int64(time.Until(exp).Seconds()), providerName, state, sd.ReturnTo)
	target := buildFrontendCallbackURL(base, s.svc.Config().Frontend.OIDCReturnPath, frag)
	// RFC 6749 §5.1 hygiene: the Location fragment carries the session tokens —
	// the response must never be cached.
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
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
	// Empty when the refresh token was delivered as a cookie (ak#271): a
	// `refresh_token=` in the URL fragment is a lie the SPA would store.
	if refreshToken != "" {
		v.Set("refresh_token", refreshToken)
	}
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
