package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/oidcstate"
	"github.com/open-rails/authkit/internal/secret"
	"github.com/open-rails/authkit/provider"
)

// flowStart is what a browser flow start records beyond the state machine's
// own state/nonce/PKCE values.
type flowStart struct {
	link   *authflow.ExternalLinkAuthorization
	stepUp *oidcstate.StateData // StepUp* fields to carry
	params map[string]string    // extra authorization parameters
	login  *loginStart
}

// loginStart is a plain login's browser context.
type loginStart struct {
	ui, popupNonce, returnTo, accountInviteToken string
	agreements                                   []iam.AgreementRef
	// dpopKey binds the session (RFC 9449 §10): a navigation's dpop_jkt, or
	// a JSON start's proof.
	dpopKey string
}

func (s *Service) handleOIDCLoginGET(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	q := r.URL.Query()
	// An invitation is a bearer credential: it never rides in a URL, where
	// history, logs and Referer keep it. The JSON start binds it to the
	// flow's server-side state instead.
	if q.Has("invite_code") {
		s.failBrowserFlow(w, r, nil, provider, errmodel.E(errmodel.CodeInvalidRequest))
		return
	}
	s.startProviderFlow(w, r, provider, flowStart{login: &loginStart{ui: q.Get("ui"), popupNonce: q.Get("popup_nonce"), returnTo: q.Get("return_to"), dpopKey: q.Get("dpop_jkt")}})
}

// handleOIDCLoginStartPOST starts a login from the page's own origin and answers
// {"auth_url","state"}; the page then navigates (or its popup does) to
// auth_url. It is the only start that accepts an account invitation.
func (s *Service) handleOIDCLoginStartPOST(w http.ResponseWriter, r *http.Request) {
	var req OIDCLoginStartRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	// The response sets the flow's state cookie; a cross-site page must not
	// bind a flow into this browser.
	if !s.cookieOriginAllowed(r) {
		fail(w, errmodel.CodeOriginNotAllowed)
		return
	}
	s.startProviderFlow(w, r, r.PathValue("provider"), flowStart{login: &loginStart{
		ui: req.UI, popupNonce: req.PopupNonce, returnTo: req.ReturnTo, accountInviteToken: req.InviteCode, agreements: req.Agreements, dpopKey: authflow.DPoPKey(r.Context()),
	}})
}

func (s *Service) handleOIDCLinkStartPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.newSignInMethodCaller(w, r)
	if !ok {
		return
	}
	freshness, err := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
	if err != nil || freshness.StepUpRequiredForSensitiveOps {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	s.startProviderFlow(w, r, r.PathValue("provider"), flowStart{link: &authflow.ExternalLinkAuthorization{UserID: claims.UserID, SessionID: claims.SessionID, AuthenticatedAt: freshness.LastAuthenticatedAt}})
}

// startProviderFlow begins a login, link or step-up flow: it generates state,
// nonce and (when the provider uses it) PKCE, binds state to this browser,
// stores the pending flow, and sends the browser to the provider. A plain GET
// login is a browser navigation and is redirected; link and step-up starts
// (and any POST) are fetch calls and receive {"auth_url","state"} JSON.
func (s *Service) startProviderFlow(w http.ResponseWriter, r *http.Request, name string, start flowStart) {
	browserNav := start.login != nil && r.Method != http.MethodPost
	reject := func(err error) {
		if browserNav {
			s.failBrowserFlow(w, r, nil, name, err)
			return
		}
		writeError(w, err)
	}
	p, ok := s.provider(name)
	if !ok {
		reject(errmodel.E(errmodel.CodeUnknownProvider))
		return
	}
	var login loginStart
	if start.login != nil {
		login = *start.login
		if login.ui != "" && login.ui != "popup" {
			reject(errmodel.E(errmodel.CodeInvalidUI))
			return
		}
		if login.dpopKey != "" && !jose.ValidThumbprint(login.dpopKey) {
			reject(errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("dpop_jkt")))
			return
		}
		if login.dpopKey == "" && s.cfg.SignIn.DPoP == config.DPoPRequired {
			reject(errmodel.E(errmodel.CodeSenderProofRequired))
			return
		}
	}

	state := secret.Token(32)
	nonce := secret.Token(16)
	verifier, challenge := "", ""
	if p.PKCE() {
		var err error
		if verifier, challenge, err = oidcstate.GeneratePKCE(); err != nil {
			reject(errmodel.Internal("pkce_generation_failed", err))
			return
		}
	}
	redirectURI, ok := s.buildRedirectURI(r, p.Name())
	if !ok {
		reject(errmodel.Internal("oidc_callback_unmounted", errors.New("no browser OIDC callback on this mount")))
		return
	}
	// AK F3: bind state to this browser so a third party can't drive a victim
	// through the callback with an attacker-issued state+code (login CSRF).
	s.setStateCookie(w, r, p, state)
	authURL, err := p.AuthCodeURL(r.Context(), provider.AuthRequest{
		State: state, Nonce: nonce, CodeChallenge: challenge, RedirectURI: redirectURI, Params: start.params,
	})
	if errors.Is(err, provider.ErrUnavailable) {
		reject(errmodel.E(errmodel.CodeProviderUnavailable))
		return
	}
	if err != nil {
		reject(errmodel.E(errmodel.CodeOIDCBeginFailed))
		return
	}
	sd := oidcstate.StateData{
		Provider:    p.Name(),
		Verifier:    verifier,
		Nonce:       nonce,
		RedirectURI: redirectURI,
		UI:          login.ui,
		PopupNonce:  login.popupNonce,
		Device:      authflow.SignInDeviceFrom(r.Context()),
	}
	if start.link != nil {
		sd.LinkUserID = start.link.UserID
		sd.LinkSessionID = start.link.SessionID
		sd.LinkAuthenticatedAt = start.link.AuthenticatedAt
	}
	if start.login != nil {
		// Anything but a same-site path is no return_to at all.
		if rt := SanitizeReturnTo(login.returnTo); rt != "/" {
			sd.ReturnTo = rt
		}
		sd.AccountInviteToken = strings.TrimSpace(login.accountInviteToken)
		sd.Agreements = login.agreements
		sd.DPoPKey = login.dpopKey
	}
	if start.stepUp != nil {
		sd.StepUpUserID = start.stepUp.StepUpUserID
		sd.StepUpSessionID = start.stepUp.StepUpSessionID
		sd.StepUpReturnTo = start.stepUp.StepUpReturnTo
		sd.StepUpStartedAt = start.stepUp.StepUpStartedAt
	}
	if err := s.svc.PutOIDCState(r.Context(), state, sd); err != nil {
		reject(errmodel.Internal("state_store_failed", err))
		return
	}
	if browserNav {
		http.Redirect(w, r, authURL, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, OIDCStart{AuthURL: authURL, State: state})
}

// handleOIDCCallbackGET completes a login, link or step-up (its state says
// which) for the IdP's GET redirect and, for response_mode=form_post
// providers, the equivalent POST (#295).
func (s *Service) handleOIDCCallbackGET(w http.ResponseWriter, r *http.Request) {
	// Every callback response carries the flow result (tokens, error, popup
	// document); none may be cached.
	w.Header().Set("Cache-Control", "no-store")
	name := r.PathValue("provider")
	p, ok := s.provider(name)
	if !ok {
		s.failBrowserFlow(w, r, nil, name, errmodel.E(errmodel.CodeUnknownProvider))
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
		s.failBrowserFlow(w, r, errSD, name, providerCallbackError(qErr))
		return
	}
	state := params.Get("state")
	code := params.Get("code")
	if state == "" || code == "" {
		s.failBrowserFlow(w, r, nil, name, errmodel.E(errmodel.CodeInvalidRequest))
		return
	}

	// AK F3: the browser completing the callback must present the state cookie
	// set at flow start. This blocks login CSRF, where an attacker supplies a
	// valid state+code captured from their own login.
	cookieOK := s.stateCookieMatches(r, p, state)
	s.clearStateCookie(w, r, p, state)
	if !cookieOK {
		s.failBrowserFlow(w, r, nil, name, errmodel.E(errmodel.CodeInvalidState))
		return
	}
	sd, ok, err := s.svc.ConsumeOIDCState(r.Context(), state)
	if err != nil || !ok || sd.Provider != name {
		s.failBrowserFlow(w, r, nil, name, errmodel.E(errmodel.CodeInvalidState))
		return
	}

	identity, err := p.Exchange(r.Context(), provider.ExchangeRequest{
		Code: code, CodeVerifier: sd.Verifier, Nonce: sd.Nonce, RedirectURI: sd.RedirectURI,
	})
	if errors.Is(err, provider.ErrUnavailable) {
		s.failBrowserFlow(w, r, &sd, name, errmodel.E(errmodel.CodeProviderUnavailable))
		return
	}
	if err != nil || strings.TrimSpace(identity.Subject) == "" {
		s.failBrowserFlow(w, r, &sd, name, errmodel.E(errmodel.CodeOIDCExchangeFailed))
		return
	}
	if s.completeOIDCStepUp(w, r, sd, name, p.Issuer(), identity.Subject, identity.AuthTime) {
		return
	}

	var link *authflow.ExternalLinkAuthorization
	if sd.LinkUserID != "" {
		link = &authflow.ExternalLinkAuthorization{UserID: sd.LinkUserID, SessionID: sd.LinkSessionID, AuthenticatedAt: sd.LinkAuthenticatedAt}
	}
	// The sign-in counts against the device that began it.
	ctx := authflow.WithDPoPKey(authflow.WithSignInDevice(r.Context(), sd.Device), sd.DPoPKey)
	out, err := s.svc.CompleteExternalLogin(ctx, authflow.ExternalLoginInput{
		Identity: authflow.ExternalIdentity{
			Provider: name, Issuer: p.Issuer(), Subject: identity.Subject,
			Email: identity.Email, EmailVerified: identity.EmailVerified && p.TrustsEmailVerification(),
			PreferredUsername: identity.PreferredUsername, DisplayName: identity.DisplayName,
		},
		Link: link, AccountInviteToken: sd.AccountInviteToken, Agreements: sd.Agreements, ReturnTo: sd.ReturnTo,
		Event: "oidc_login", UserAgent: r.UserAgent(), IP: s.requestIP(r),
	})
	if err != nil {
		s.failBrowserFlow(w, r, &sd, name, err)
		return
	}
	if out.Kind == authflow.LoginProviderLinked {
		if wantsJSONResponse(r) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		fragment := url.Values{"flow": {"link"}, "result": {"success"}, "provider": {name}}
		http.Redirect(w, r, s.frontendCallbackURL("#"+fragment.Encode()), http.StatusFound)
		return
	}
	out.ReturnTo = sd.ReturnTo
	res, err := s.authResult(w, r, out, authExtras{})
	if err != nil {
		s.failBrowserFlow(w, r, &sd, name, err)
		return
	}
	s.emitBrowserResult(w, r, &sd, name, res)
}

// emitBrowserResult hands a browser flow its AuthResult, a session or its
// next step alike. A callback asked for JSON answers it. A popup or redirect
// carries only a one-time code that POST {api}/oidc/exchange trades for it,
// so no token rides a URL or a postMessage.
func (s *Service) emitBrowserResult(w http.ResponseWriter, r *http.Request, sd *oidcstate.StateData, provider string, res AuthResult) {
	if wantsJSONResponse(r) {
		writeAuthResult(w, res)
		return
	}
	code, err := s.putOIDCResult(r, res)
	if err != nil {
		s.failBrowserFlow(w, r, sd, provider, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if sd.StepUpUserID != "" {
		http.Redirect(w, r, stepUpReturnURL(sd.StepUpReturnTo, url.Values{"code": {code}}), http.StatusFound)
		return
	}
	if targetOrigin, ok := originFromBaseURL(s.cfg.Frontend.BaseURL); ok && sd.UI == "popup" {
		writePopupDocument(w, buildPopupHTML(oidcPopupMessage{Type: oidcPopupType, Nonce: sd.PopupNonce, Provider: provider, Code: &code}, targetOrigin))
		return
	}
	fragment := url.Values{"code": {code}}
	if state := callbackParams(r).Get("state"); state != "" {
		fragment.Set("state", state)
	}
	http.Redirect(w, r, s.frontendCallbackURL("#"+fragment.Encode()), http.StatusFound)
}

// putOIDCResult stores res for a new one-time code. A cookie mount's refresh
// token already went to the cookie (authResult), so none is stored.
func (s *Service) putOIDCResult(r *http.Request, res AuthResult) (string, error) {
	raw, err := json.Marshal(res)
	if err != nil {
		return "", errmodel.Internal("oidc_result_store_failed", err)
	}
	code := secret.Token(32)
	if err := s.svc.PutOIDCResult(r.Context(), code, raw); err != nil {
		return "", errmodel.Internal("oidc_result_store_failed", err)
	}
	return code, nil
}

// handleOIDCExchangePOST trades a browser OIDC result's one-time code for its
// AuthResult, once, within two minutes.
func (s *Service) handleOIDCExchangePOST(w http.ResponseWriter, r *http.Request) {
	var req OIDCExchangeRequest
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Code) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	raw, ok, err := s.svc.ConsumeOIDCResult(r.Context(), strings.TrimSpace(req.Code))
	if err != nil {
		serverErr(w, "oidc_result_lookup_failed", err)
		return
	}
	var res AuthResult
	if !ok || json.Unmarshal(raw, &res) != nil {
		fail(w, errmodel.CodeInvalidState)
		return
	}
	writeAuthResult(w, res)
}

// oidcPopupType is the one message a popup posts to its opener: the result's
// one-time code, or the error that ended the flow.
const oidcPopupType = "AUTHKIT_OIDC_RESULT"

type oidcPopupMessage struct {
	Type     string  `json:"type"`
	Nonce    string  `json:"nonce"`
	Provider string  `json:"provider"`
	Code     *string `json:"code,omitempty"`
	Error    *string `json:"error,omitempty"`
}

// frontendCallbackURL is the app's OIDC return page with fragment.
func (s *Service) frontendCallbackURL(fragment string) string {
	return strings.TrimRight(s.cfg.Frontend.BaseURL, "/") + s.cfg.Frontend.OIDCReturnPath + fragment
}

// stepUpReturnURL is a step-up's return_to (same-origin) with its result in
// the fragment.
func stepUpReturnURL(returnTo string, fragment url.Values) string {
	u, err := url.Parse(SanitizeReturnTo(returnTo))
	if err != nil || u == nil {
		u = &url.URL{Path: "/"}
	}
	u.Fragment = ""
	return u.String() + "#" + fragment.Encode()
}

func buildPopupHTML(message oidcPopupMessage, targetOrigin string) []byte {
	payloadJSON, _ := json.Marshal(message)
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
