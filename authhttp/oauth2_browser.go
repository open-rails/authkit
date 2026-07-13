package authhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
	"io"
	stdlog "log"
	"net/http"
	"net/url"
	"strings"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/oidckit"
)

var errProviderAlreadyLinked = errors.New("provider_already_linked")

// errProviderLinkFailed signals that the load-bearing provider-link write failed
// during an OIDC callback. We fail the callback (rather than reporting success
// with no persisted link) so the next login can't diverge into a duplicate
// account or a link-required dead-end. See authkit #90 (AK-IMPL-2c).
var errProviderLinkFailed = errors.New("provider_link_failed")

// errAccountExistsLinkRequired signals that an OAuth2 identity is not yet linked
// but its asserted email already belongs to a local account. We refuse to
// silently link by email (the C-2 account-takeover vector); the user must sign
// in and link the provider via the authenticated /oidc/link/start flow.
var errAccountExistsLinkRequired = errors.New("account_exists_link_required")

func strptr(s string) *string {
	return &s
}

func (s *Service) handleOAuthLoginGET(w http.ResponseWriter, r *http.Request, provider string) {
	claimsUserID := ""
	if r.URL.Query().Get("link") == "1" || strings.EqualFold(r.URL.Query().Get("link"), "true") {
		s.failBrowserFlow(w, r, nil, provider, http.StatusUnauthorized, ErrAuthRequiredForLink)
		return
	}
	s.startOAuthBrowserFlow(w, r, provider, claimsUserID, "", "", sanitizeReturnTo(r.URL.Query().Get("return_to")))
}

func (s *Service) handleOAuthLinkStartPOST(w http.ResponseWriter, r *http.Request, provider string) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	s.startOAuthBrowserFlow(w, r, provider, claims.UserID, "", "", "")
}

func (s *Service) handleOAuthStepUpStartPOST(w http.ResponseWriter, r *http.Request, provider string) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}
	var body struct {
		ReturnTo string `json:"return_to"`
	}
	_ = decodeJSON(r, &body)

	cfg, ok := s.oauth2Provider(provider)
	if !ok {
		badRequest(w, ErrUnknownProvider)
		return
	}
	if !s.userHasLinkedIssuerProvider(r, claims.UserID, cfg.Issuer, cfg.Name) {
		badRequest(w, ErrProviderNotLinked)
		return
	}
	s.startOAuthBrowserFlow(w, r, cfg.Name, "", claims.UserID, sanitizeReturnTo(body.ReturnTo), "")
}

func (s *Service) startOAuthBrowserFlow(w http.ResponseWriter, r *http.Request, provider, linkUserID, stepUpUserID, stepUpReturnTo, returnTo string) {
	// Plain GET logins are browser navigations; link/step-up starts (and any
	// POST) are fetch calls that receive auth_url JSON below, so their errors
	// stay JSON too.
	browserNav := strings.TrimSpace(linkUserID) == "" && strings.TrimSpace(stepUpUserID) == "" && r.Method != http.MethodPost
	fail := func(status int, code ErrorCode) {
		if browserNav {
			s.failBrowserFlow(w, r, nil, provider, status, code)
			return
		}
		sendErr(w, status, code)
	}
	cfg, ok := s.oauth2Provider(provider)
	if !ok {
		fail(http.StatusBadRequest, ErrUnknownProvider)
		return
	}
	if s.rateLimited(w, r, RLOIDCStart) {
		return
	}
	rp, ok := s.oidcManager().Provider(cfg.Name)
	if !ok || strings.TrimSpace(rp.ClientID) == "" {
		fail(http.StatusBadRequest, ErrUnknownProvider)
		return
	}

	redirectURI := s.buildRedirectURI(r, cfg.Name)
	state := randB64(32)
	// AK F3: bind state to this browser so a third party can't drive a victim
	// through the callback with an attacker-issued state+code (login CSRF).
	s.setStateCookie(w, r, state)
	verifier := ""
	challenge := ""
	if cfg.PKCE {
		var err error
		verifier, challenge, err = oidckit.GeneratePKCE()
		if err != nil {
			fail(http.StatusInternalServerError, ErrPKCEGenerationFailed)
			return
		}
	}
	ui := r.URL.Query().Get("ui")
	if ui != "" && ui != "popup" {
		fail(http.StatusBadRequest, ErrInvalidUI)
		return
	}
	popupNonce := r.URL.Query().Get("popup_nonce")
	sessionID := ""
	if strings.TrimSpace(stepUpUserID) != "" {
		if claims, ok := verify.ClaimsFromContext(r.Context()); ok {
			sessionID = claims.SessionID
		}
	}
	if err := s.stateCache().Put(r.Context(), state, oidckit.StateData{
		Provider:           cfg.Name,
		Verifier:           verifier,
		RedirectURI:        redirectURI,
		LinkUserID:         linkUserID,
		ReturnTo:           returnTo,
		AccountInviteToken: strings.TrimSpace(r.URL.Query().Get("account_invite_token")),
		StepUpUserID:       stepUpUserID,
		StepUpSessionID:    sessionID,
		StepUpReturnTo:     stepUpReturnTo,
		UI:                 ui,
		PopupNonce:         popupNonce,
	}); err != nil {
		fail(http.StatusInternalServerError, ErrStateStoreFailed)
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
	if strings.TrimSpace(linkUserID) != "" || strings.TrimSpace(stepUpUserID) != "" || r.Method == http.MethodPost {
		writeJSON(w, http.StatusOK, map[string]any{"auth_url": authURL, "state": state})
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Service) handleOAuthCallbackGET(w http.ResponseWriter, r *http.Request, provider string) {
	cfg, ok := s.oauth2Provider(provider)
	if !ok {
		s.failBrowserFlow(w, r, nil, provider, http.StatusBadRequest, ErrUnknownProvider)
		return
	}
	if s.rateLimited(w, r, RLOIDCCallback) {
		return
	}
	// The IdP echoes state on error redirects too; recover the flow context
	// when this browser really started the flow, so the error lands where the
	// flow expects it (popup message / step-up return / frontend fragment).
	if qErr := r.URL.Query().Get("error"); qErr != "" {
		errSD := s.recoverCallbackState(w, r, cfg.Name)
		s.failBrowserFlow(w, r, errSD, cfg.Name, http.StatusBadRequest, sanitizeProviderErrorCode(qErr))
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		s.failBrowserFlow(w, r, nil, cfg.Name, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	// AK F3: the browser completing the callback must present the state cookie set
	// at flow start. This blocks login CSRF, where an attacker supplies a valid
	// state+code captured from their own login.
	cookieOK := stateCookieMatches(r, state)
	clearStateCookie(w)
	if !cookieOK {
		s.failBrowserFlow(w, r, nil, cfg.Name, http.StatusBadRequest, ErrInvalidState)
		return
	}

	oidcCfg := s.oidcCfg()
	sd, ok, err := consumeState(r.Context(), oidcCfg.StateCache, state)
	if err != nil || !ok || sd.Provider != cfg.Name {
		s.failBrowserFlow(w, r, nil, cfg.Name, http.StatusBadRequest, ErrInvalidState)
		return
	}

	rp, ok := oidcCfg.Manager.Provider(cfg.Name)
	if !ok || strings.TrimSpace(rp.ClientID) == "" || strings.TrimSpace(rp.ClientSecret) == "" {
		s.failBrowserFlow(w, r, &sd, cfg.Name, http.StatusBadRequest, ErrUnknownProvider)
		return
	}
	token, err := s.exchangeOAuthCode(r, cfg, rp.ClientID, rp.ClientSecret, code, sd.RedirectURI, sd.Verifier)
	if err != nil {
		s.failBrowserFlow(w, r, &sd, cfg.Name, http.StatusUnauthorized, ErrExchangeFailed)
		return
	}
	info, err := s.fetchOAuthUserInfo(r, cfg, token)
	if err != nil || strings.TrimSpace(info.Subject) == "" {
		s.failBrowserFlow(w, r, &sd, cfg.Name, http.StatusUnauthorized, ErrUserinfoFailed)
		return
	}

	if s.completeOAuthStepUp(w, r, sd, cfg, info.Subject) {
		return
	}

	userID, created, err := s.resolveOAuthUser(r, cfg, sd, info)
	if err != nil {
		if errors.Is(err, errProviderAlreadyLinked) {
			s.failBrowserFlow(w, r, &sd, cfg.Name, http.StatusBadRequest, ErrProviderAlreadyLinked)
			return
		}
		if errors.Is(err, errAccountExistsLinkRequired) {
			s.accountExistsLinkRequired(w, r, &sd, cfg.Name)
			return
		}
		if errors.Is(err, authkit.ErrRegistrationDisabled) {
			s.failBrowserFlow(w, r, &sd, cfg.Name, http.StatusForbidden, ErrRegistrationDisabled)
			return
		}
		if errors.Is(err, errProviderLinkFailed) {
			s.failBrowserFlow(w, r, &sd, cfg.Name, http.StatusInternalServerError, ErrProviderLinkFailed)
			return
		}
		s.failBrowserFlow(w, r, &sd, cfg.Name, http.StatusInternalServerError, ErrUserCreationFailed)
		return
	}
	s.finishBrowserLogin(w, r, userID, info.Email, cfg.Name, "oauth_login:"+cfg.Name, created, sd)
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
	resp, err := defaultOutboundHTTPClient.Do(req)
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

func (s *Service) completeOAuthStepUp(w http.ResponseWriter, r *http.Request, sd oidckit.StateData, cfg authprovider.Provider, subject string) bool {
	if strings.TrimSpace(sd.StepUpUserID) == "" {
		return false
	}
	userID, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), cfg.Issuer, subject)
	if err != nil || userID != sd.StepUpUserID {
		redirectStepUpResult(w, r, sd.StepUpReturnTo, "failed")
		return true
	}
	if err := s.svc.MarkSessionAuthenticatedWithMethods(r.Context(), sd.StepUpUserID, sd.StepUpSessionID, []string{"oauth"}); err != nil {
		redirectStepUpResult(w, r, sd.StepUpReturnTo, "failed")
		return true
	}
	return s.emitStepUpResult(w, r, sd, cfg.Name)
}

func (s *Service) resolveOAuthUser(r *http.Request, cfg authprovider.Provider, sd oidckit.StateData, info oauth2UserInfo) (string, bool, error) {
	emailPtr := strptr(info.Email)
	if sd.LinkUserID != "" {
		if uid0, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), cfg.Issuer, info.Subject); err == nil && uid0 != "" && uid0 != sd.LinkUserID {
			return "", false, errProviderAlreadyLinked
		}
		// The provider link is the load-bearing write: if it fails we must NOT
		// report success, or the next login won't find the link and will diverge
		// (duplicate account / link-required dead-end). Fail the callback so the
		// user retries against a still-consistent state.
		if err := s.svc.LinkProviderByIssuer(r.Context(), sd.LinkUserID, cfg.Issuer, cfg.Name, info.Subject, emailPtr); err != nil {
			stdlog.Printf("[authkit/security] error: provider link write failed (user=%s issuer=%s); failing OIDC callback: %v", sd.LinkUserID, cfg.Issuer, err)
			return "", false, fmt.Errorf("%w: %v", errProviderLinkFailed, err)
		}
		if strings.TrimSpace(info.Preferred) != "" {
			if err := s.svc.SetProviderUsername(r.Context(), sd.LinkUserID, cfg.Issuer, info.Subject, info.Preferred); err != nil {
				stdlog.Printf("[authkit/security] warning: SetProviderUsername failed (user=%s issuer=%s); link succeeded, username not updated: %v", sd.LinkUserID, cfg.Issuer, err)
			}
		}
		return sd.LinkUserID, false, nil
	}
	if uid, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), cfg.Issuer, info.Subject); err == nil && uid != "" {
		if strings.TrimSpace(info.Preferred) != "" {
			if err := s.svc.SetProviderUsername(r.Context(), uid, cfg.Issuer, info.Subject, info.Preferred); err != nil {
				stdlog.Printf("[authkit/security] warning: SetProviderUsername failed (user=%s issuer=%s); login succeeded, username not updated: %v", uid, cfg.Issuer, err)
			}
		}
		return uid, false, nil
	}
	// SECURITY (C-2): never silently link a fresh provider identity to a
	// pre-existing local account by matching its asserted email. An IdP that
	// asserts (or lies about) a victim's email would otherwise take over the
	// victim's account with no proof the caller controls it. If a local account
	// already owns this email, refuse and require the user to sign in and link
	// the provider via the authenticated /oidc/link/start flow.
	if strings.TrimSpace(info.Email) != "" {
		if u, err := s.svc.GetUserByEmail(r.Context(), info.Email); err == nil && u != nil {
			return "", false, errAccountExistsLinkRequired
		}
	}
	// No existing account for this provider identity or email. Auto-creating a
	// new account is a public registration path. InviteOnly requires an unbound
	// account invite token carried from flow start.
	if s.svc.Config().Registration.NativeUserMode == embedded.RegistrationModeInviteOnly {
		if strings.TrimSpace(info.Email) == "" {
			return "", false, authkit.ErrRegistrationDisabled
		}
		allowed, err := s.svc.RegistrationAllowedForEmailWithInvite(r.Context(), info.Email, sd.AccountInviteToken)
		if err != nil {
			return "", false, err
		}
		if !allowed {
			return "", false, authkit.ErrRegistrationDisabled
		}
	} else if s.publicRegistrationDisabled() {
		return "", false, authkit.ErrRegistrationDisabled
	}
	username := s.svc.DeriveUsernameForOAuth(r.Context(), cfg.Name, info.Preferred, info.Email, info.Display)
	u, err := s.svc.CreateUser(r.Context(), info.Email, username)
	if err != nil || u == nil {
		return "", false, errors.New("user_creation_failed")
	}
	// Link is load-bearing (see branch above). On failure, fail the callback
	// rather than leaving the just-created user unlinked and reporting success.
	// NOTE: without a create+link transaction a failure here leaves an orphan
	// user row (no provider link); logged CRITICAL for cleanup. Follow-up:
	// atomic create+link (authkit #88 tx-aware provisioning) closes that window.
	if err := s.svc.LinkProviderByIssuer(r.Context(), u.ID, cfg.Issuer, cfg.Name, info.Subject, emailPtr); err != nil {
		stdlog.Printf("[authkit/security] CRITICAL: provider link write failed after user creation (orphan user=%s issuer=%s subject=%s); failing OIDC callback — manual cleanup may be required: %v", u.ID, cfg.Issuer, info.Subject, err)
		return "", false, fmt.Errorf("%w: %v", errProviderLinkFailed, err)
	}
	if info.EmailVerified && strings.TrimSpace(info.Email) != "" {
		if err := s.svc.SetEmailVerified(r.Context(), u.ID, true); err != nil {
			stdlog.Printf("[authkit/security] warning: SetEmailVerified failed for new user %s (recoverable; user+link created): %v", u.ID, err)
		}
	}
	if err := s.svc.ConsumeAccountRegistrationInvite(r.Context(), info.Email, u.ID, sd.AccountInviteToken); err != nil {
		return "", false, err
	}
	if strings.TrimSpace(info.Preferred) != "" {
		if err := s.svc.SetProviderUsername(r.Context(), u.ID, cfg.Issuer, info.Subject, info.Preferred); err != nil {
			stdlog.Printf("[authkit/security] warning: SetProviderUsername failed for new user %s (cosmetic): %v", u.ID, err)
		}
	}
	return u.ID, true, nil
}
