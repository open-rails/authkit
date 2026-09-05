package authhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"net/url"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/oidckit"
	"github.com/open-rails/authkit/verify"
)

// errProviderLinkFailed signals that the load-bearing provider-link write failed
// during a callback. We fail the callback (rather than reporting success with
// no persisted link) so the next login can't diverge into a duplicate account
// or a link-required dead-end. See authkit #90 (AK-IMPL-2c).
var errProviderLinkFailed = errors.New("provider_link_failed")

// errAccountExistsLinkRequired signals that a provider identity is not yet
// linked but its asserted email already belongs to a local account. We refuse
// to silently link by email (the C-2 account-takeover vector); the user must
// sign in and link the provider via the authenticated /oidc/link/start flow.
var errAccountExistsLinkRequired = errors.New("account_exists_link_required")

// flowStart is what a browser flow start records beyond the state machine's
// own state/nonce/PKCE values.
type flowStart struct {
	linkUserID string
	stepUp     *oidckit.StateData // StepUp* fields to carry
	params     map[string]string  // extra authorization parameters
}

func (s *Service) handleOIDCLoginGET(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if r.URL.Query().Get("link") == "1" || strings.EqualFold(r.URL.Query().Get("link"), "true") {
		s.failBrowserFlow(w, r, nil, provider, http.StatusUnauthorized, ErrAuthRequiredForLink)
		return
	}
	s.startProviderFlow(w, r, provider, flowStart{})
}

func (s *Service) handleOIDCLinkStartPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}
	s.startProviderFlow(w, r, r.PathValue("provider"), flowStart{linkUserID: claims.UserID})
}

// startProviderFlow begins a login, link or step-up flow: it generates state,
// nonce and (when the provider uses it) PKCE, binds state to this browser,
// stores the pending flow, and sends the browser to the provider. A plain GET
// login is a browser navigation and is redirected; link and step-up starts
// (and any POST) are fetch calls and receive {"auth_url","state"} JSON.
func (s *Service) startProviderFlow(w http.ResponseWriter, r *http.Request, name string, start flowStart) {
	browserNav := start.linkUserID == "" && start.stepUp == nil && r.Method != http.MethodPost
	fail := func(status int, code ErrorCode) {
		if browserNav {
			s.failBrowserFlow(w, r, nil, name, status, code)
			return
		}
		sendErr(w, status, code)
	}
	p, ok := s.provider(name)
	if !ok {
		fail(http.StatusBadRequest, ErrUnknownProvider)
		return
	}
	if s.rateLimited(w, r, RLOIDCStart) {
		return
	}
	ui := ""
	popupNonce := ""
	if browserNav {
		ui = r.URL.Query().Get("ui")
		if ui != "" && ui != "popup" {
			fail(http.StatusBadRequest, ErrInvalidUI)
			return
		}
		popupNonce = r.URL.Query().Get("popup_nonce")
	}

	state := authcore.RandB64(32)
	nonce := authcore.RandB64(16)
	verifier, challenge := "", ""
	if p.PKCE() {
		var err error
		if verifier, challenge, err = oidckit.GeneratePKCE(); err != nil {
			fail(http.StatusInternalServerError, ErrPKCEGenerationFailed)
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
	if err != nil {
		fail(http.StatusBadRequest, ErrOIDCBeginFailed)
		return
	}
	sd := oidckit.StateData{
		Provider:    p.Name(),
		Verifier:    verifier,
		Nonce:       nonce,
		RedirectURI: redirectURI,
		LinkUserID:  start.linkUserID,
		UI:          ui,
		PopupNonce:  popupNonce,
	}
	if browserNav {
		sd.ReturnTo = sanitizeReturnTo(r.URL.Query().Get("return_to"))
		sd.AccountInviteToken = strings.TrimSpace(r.URL.Query().Get("account_invite_token"))
	}
	if start.stepUp != nil {
		sd.StepUpUserID = start.stepUp.StepUpUserID
		sd.StepUpSessionID = start.stepUp.StepUpSessionID
		sd.StepUpReturnTo = start.stepUp.StepUpReturnTo
		sd.StepUpStartedAt = start.stepUp.StepUpStartedAt
	}
	if err := s.stateCache().Put(r.Context(), state, sd); err != nil {
		fail(http.StatusInternalServerError, ErrStateStoreFailed)
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
		s.failBrowserFlow(w, r, nil, name, http.StatusBadRequest, ErrUnknownProvider)
		return
	}
	name = p.Name()
	// The IdP echoes state on error redirects too; recover the flow context
	// when this browser really started the flow, so the error lands where the
	// flow expects it (popup message / step-up return / frontend fragment).
	params := callbackParams(r)
	if qErr := params.Get("error"); qErr != "" {
		logIdPCallbackError(name, r)
		errSD := s.recoverCallbackState(w, r, name)
		s.failBrowserFlow(w, r, errSD, name, http.StatusBadRequest, sanitizeProviderErrorCode(qErr))
		return
	}
	state := params.Get("state")
	code := params.Get("code")
	if state == "" || code == "" {
		s.failBrowserFlow(w, r, nil, name, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	// AK F3: the browser completing the callback must present the state cookie
	// set at flow start. This blocks login CSRF, where an attacker supplies a
	// valid state+code captured from their own login.
	cookieOK := stateCookieMatches(r, state)
	clearStateCookie(w, state)
	if !cookieOK {
		s.failBrowserFlow(w, r, nil, name, http.StatusBadRequest, ErrInvalidState)
		return
	}
	sd, ok, err := consumeState(r.Context(), s.stateCache(), state)
	if err != nil || !ok || sd.Provider != name {
		s.failBrowserFlow(w, r, nil, name, http.StatusBadRequest, ErrInvalidState)
		return
	}

	identity, err := p.Exchange(r.Context(), authprovider.ExchangeRequest{
		Code: code, CodeVerifier: sd.Verifier, Nonce: sd.Nonce, RedirectURI: sd.RedirectURI,
	})
	if err != nil || strings.TrimSpace(identity.Subject) == "" {
		s.failBrowserFlow(w, r, &sd, name, http.StatusUnauthorized, ErrOIDCExchangeFailed)
		return
	}
	if s.completeOIDCStepUp(w, r, sd, name, p.Issuer(), identity.Subject, identity.AuthTime) {
		return
	}

	userID, created, err := s.resolveProviderUser(r, p, sd, identity)
	if err != nil {
		switch {
		case errors.Is(err, authkit.ErrProviderAlreadyLinked):
			s.failBrowserFlow(w, r, &sd, name, http.StatusConflict, ErrProviderAlreadyLinked)
		case errors.Is(err, authkit.ErrProviderChangeRequiresUnlink):
			s.failBrowserFlow(w, r, &sd, name, http.StatusConflict, ErrProviderChangeRequiresUnlink)
		case errors.Is(err, errAccountExistsLinkRequired):
			s.accountExistsLinkRequired(w, r, &sd, name)
		case errors.Is(err, authkit.ErrRegistrationDisabled):
			s.failBrowserFlow(w, r, &sd, name, http.StatusForbidden, ErrRegistrationDisabled)
		case errors.Is(err, errProviderLinkFailed):
			s.failBrowserFlow(w, r, &sd, name, http.StatusInternalServerError, ErrProviderLinkFailed)
		default:
			s.failBrowserFlow(w, r, &sd, name, http.StatusInternalServerError, ErrUserCreationFailed)
		}
		return
	}
	s.finishBrowserLogin(w, r, userID, name, "oidc_login", created, sd)
}

// resolveProviderUser maps a verified provider identity to a local user: the
// explicit link target, the already-linked account, or a newly registered one.
func (s *Service) resolveProviderUser(r *http.Request, p authprovider.Provider, sd oidckit.StateData, identity authprovider.Identity) (string, bool, error) {
	ctx := r.Context()
	issuer, name := p.Issuer(), p.Name()
	var emailPtr *string
	if e := strings.TrimSpace(identity.Email); e != "" {
		emailPtr = &e
	}
	setUsername := func(userID, note string) {
		if strings.TrimSpace(identity.PreferredUsername) == "" {
			return
		}
		if err := s.svc.SetProviderUsername(ctx, userID, issuer, identity.Subject, identity.PreferredUsername); err != nil {
			stdlog.Printf("[authkit/security] warning: SetProviderUsername failed (user=%s issuer=%s); %s: %v", userID, issuer, note, err)
		}
	}

	if sd.LinkUserID != "" {
		if uid0, _, err := s.svc.GetProviderLinkByIssuer(ctx, issuer, identity.Subject); err == nil && uid0 != "" && uid0 != sd.LinkUserID {
			return "", false, authkit.ErrProviderAlreadyLinked
		}
		// The provider link is the load-bearing write: if it fails we must NOT
		// report success, or the next login won't find the link and will diverge
		// (duplicate account / link-required dead-end).
		if err := s.svc.LinkProviderByIssuer(ctx, sd.LinkUserID, issuer, name, identity.Subject, emailPtr); err != nil {
			if errors.Is(err, authkit.ErrProviderAlreadyLinked) || errors.Is(err, authkit.ErrProviderChangeRequiresUnlink) {
				return "", false, err
			}
			stdlog.Printf("[authkit/security] error: provider link write failed (user=%s issuer=%s); failing OIDC callback: %v", sd.LinkUserID, issuer, err)
			return "", false, fmt.Errorf("%w: %w", errProviderLinkFailed, err)
		}
		setUsername(sd.LinkUserID, "link succeeded, username not updated")
		return sd.LinkUserID, false, nil
	}
	if uid, _, err := s.svc.GetProviderLinkByIssuer(ctx, issuer, identity.Subject); err == nil && uid != "" {
		setUsername(uid, "login succeeded, username not updated")
		return uid, false, nil
	}

	// Trust the IdP's email only when it is explicitly verified; an absent or
	// false claim binds no address (defense in depth, ak#284).
	accountEmail := ""
	if identity.EmailVerified {
		accountEmail = strings.TrimSpace(identity.Email)
	}
	// SECURITY (C-2): never silently link a fresh provider identity to a
	// pre-existing local account by matching its asserted email. An IdP that
	// asserts (or lies about) a victim's email would otherwise take over the
	// victim's account with no proof the caller controls it. If a local account
	// already owns this email, refuse and require the user to sign in and link
	// the provider via the authenticated /oidc/link/start flow.
	if accountEmail != "" {
		if u, err := s.svc.GetUserByEmail(ctx, accountEmail); err == nil && u != nil {
			return "", false, errAccountExistsLinkRequired
		}
	}
	// No existing account for this provider identity or email. Auto-creating a
	// new account is a public registration path. InviteOnly requires an unbound
	// account invite token carried from flow start.
	if s.svc.Config().Registration.NativeUserMode == embedded.RegistrationModeInviteOnly {
		allowed, err := s.svc.RegistrationAllowedForEmailWithInvite(ctx, accountEmail, sd.AccountInviteToken)
		if err != nil {
			return "", false, err
		}
		if !allowed {
			return "", false, authkit.ErrRegistrationDisabled
		}
	} else if s.publicRegistrationDisabled() {
		return "", false, authkit.ErrRegistrationDisabled
	}
	username := s.svc.DeriveUsernameForOAuth(ctx, name, identity.PreferredUsername, accountEmail, identity.DisplayName)
	u, err := s.svc.CreateUser(ctx, accountEmail, username)
	if err != nil || u == nil {
		return "", false, errors.New("user_creation_failed")
	}
	// Link is load-bearing (see branch above). On failure, fail the callback
	// rather than leaving the just-created user unlinked and reporting success.
	// NOTE: without a create+link transaction a failure here leaves an orphan
	// user row (no provider link); logged CRITICAL for cleanup.
	if err := s.svc.LinkProviderByIssuer(ctx, u.ID, issuer, name, identity.Subject, emailPtr); err != nil {
		stdlog.Printf("[authkit/security] CRITICAL: provider link write failed after user creation (orphan user=%s issuer=%s subject=%s); failing OIDC callback — manual cleanup may be required: %v", u.ID, issuer, identity.Subject, err)
		return "", false, fmt.Errorf("%w: %w", errProviderLinkFailed, err)
	}
	if accountEmail != "" {
		if err := s.svc.SetEmailVerified(ctx, u.ID, true); err != nil {
			stdlog.Printf("[authkit/security] warning: SetEmailVerified failed for new user %s (recoverable; user+link created): %v", u.ID, err)
		}
	}
	if err := s.svc.ConsumeAccountRegistrationInvite(ctx, accountEmail, u.ID, sd.AccountInviteToken); err != nil {
		return "", false, err
	}
	setUsername(u.ID, "cosmetic")
	return u.ID, true, nil
}

// finishBrowserLogin is the shared post-resolve tail of the browser callback:
// issue session + access token (with the same 2FA-enrollment / banned /
// failure handling), log the session, send a welcome on first creation, and
// emit the result as a popup postMessage, a JSON body, or a fragment redirect.
func (s *Service) finishBrowserLogin(w http.ResponseWriter, r *http.Request, userID, providerName, sessionEvent string, created bool, sd oidckit.StateData) {
	extra := map[string]any{"provider": providerName}
	sid, rt, _, err := s.svc.IssueRefreshSessionWithAuthMethods(r.Context(), userID, r.UserAgent(), nil, []string{"oauth"})
	if err != nil {
		if errors.Is(err, authkit.ErrTwoFAEnrollmentRequired) {
			s.browser2FAEnrollmentRequired(w, r, userID, providerName, sd)
			return
		}
		if errors.Is(err, authkit.ErrUserBanned) {
			s.failBrowserFlow(w, r, &sd, providerName, http.StatusUnauthorized, ErrUserBanned)
			return
		}
		s.failBrowserFlow(w, r, &sd, providerName, http.StatusInternalServerError, ErrSessionIssueFailed)
		return
	}
	extra["sid"] = sid
	token, exp, err := s.svc.MintAccessToken(r.Context(), userID, extra)
	if err != nil {
		if errors.Is(err, authkit.ErrUserBanned) {
			s.failBrowserFlow(w, r, &sd, providerName, http.StatusUnauthorized, ErrUserBanned)
			return
		}
		s.failBrowserFlow(w, r, &sd, providerName, http.StatusInternalServerError, ErrTokenIssueFailed)
		return
	}

	ua := r.UserAgent()
	ip := remoteIP(r)
	uaPtr, ipPtr := &ua, &ip
	s.svc.LogSessionCreated(r.Context(), userID, sessionEvent, sid, ipPtr, uaPtr)

	if created {
		s.svc.SendWelcome(r.Context(), userID)
	}

	// ak#271: the popup document and the fragment redirect both hand the
	// browser its tokens in script-readable form by design. The ACCESS token
	// has to stay there — it is short-lived and the SPA builds the
	// Authorization header from it — but the durable refresh token moves to
	// the cookie, which these same-origin responses can set.
	if sd.UI == "popup" {
		targetOrigin, ok := originFromBaseURL(s.svc.Config().Frontend.BaseURL)
		if !ok {
			s.failBrowserFlow(w, r, &sd, providerName, http.StatusInternalServerError, ErrInvalidBaseURL)
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

	if strings.EqualFold(r.URL.Query().Get("format"), "json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		// Provider email is descriptive metadata; return the account's own
		// nullable address, including on an explicit provider-link callback.
		user, err := s.svc.AdminGetUser(r.Context(), userID)
		if err != nil || user == nil {
			s.failBrowserFlow(w, r, &sd, providerName, http.StatusInternalServerError, ErrUserLookupFailed)
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

// accountExistsLinkRequired is the C-2-safe outcome for a callback whose
// (issuer, sub) is not yet linked but whose asserted email already belongs to a
// local account. We refuse to silently link the identity (that is the
// account-takeover vector) and signal that the user must sign in and link the
// provider explicitly via the authenticated /oidc/link/start flow. 409 Conflict
// (JSON callers) / the browser error contract, with a stable machine-readable
// code so frontends can route to the link flow.
func (s *Service) accountExistsLinkRequired(w http.ResponseWriter, r *http.Request, sd *oidckit.StateData, provider string) {
	s.failBrowserFlow(w, r, sd, provider, http.StatusConflict, ErrAccountExistsLinkRequired)
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
