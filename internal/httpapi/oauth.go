package httpapi

// The authorization server's protocol endpoints (#430, #437): issuer metadata
// (RFC 8414, OIDC Discovery), authorize (RFC 6749 §4.1 with RFC 7636 PKCE and
// RFC 8707 resource indicators), token, userinfo and RP-initiated logout.
// They answer OAuth's own error format, not AuthKit's envelope. Validation
// that does not need state lives here; the engine owns requests, codes and
// tokens.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/dpop"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/secret"
)

const (
	maxOAuthFormBytes  = 64 << 10
	maxOAuthParamBytes = 4 << 10
)

// oauthURL is the absolute URL of an endpoint beneath the issuer's path.
func (s *Service) oauthURL(path string) string {
	return strings.TrimRight(s.http.PublicURL, "/") + path
}

func (s *Service) handleOAuthMetadata(w http.ResponseWriter, _ *http.Request) {
	as := s.cfg.AuthorizationServer
	groups := config.GroupClientsEnabled(as)
	scopes := []string{"openid", "profile", "email", "phone"}
	for _, r := range as.Resources {
		for _, scope := range r.Scopes {
			if !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
	}
	grants, detailTypes := []string{}, []string{}
	public, confidential := false, false
	for _, c := range as.Clients {
		for _, g := range c.GrantTypes {
			if !slices.Contains(grants, string(g)) {
				grants = append(grants, string(g))
			}
		}
		for _, typ := range c.AuthorizationDetailsTypes {
			if !slices.Contains(detailTypes, typ) {
				detailTypes = append(detailTypes, typ)
			}
		}
		confidential = confidential || config.OAuthClientConfidential(c)
		public = public || !config.OAuthClientConfidential(c)
	}
	authMethods := []string{}
	if public || groups {
		authMethods = append(authMethods, "none")
	}
	if confidential || groups {
		authMethods = append(authMethods, "client_secret_basic")
	}
	if confidential {
		authMethods = append(authMethods, "client_secret_post")
	}
	var assertionAlgs []string
	if groups {
		authMethods = append(authMethods, "private_key_jwt")
		assertionAlgs = []string{"RS256", "ES256", "EdDSA"}
		for _, g := range []config.OAuthGrantType{config.GrantAuthorizationCode, config.GrantRefreshToken} {
			if !slices.Contains(grants, string(g)) {
				grants = append(grants, string(g))
			}
		}
	}
	algs := []string{}
	for _, k := range s.svc.JWKS().Keys {
		if k.Alg != "" && !slices.Contains(algs, k.Alg) {
			algs = append(algs, k.Alg)
		}
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	// A public document every browser client reads first.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, OAuthServerMetadata{
		Issuer:                           s.cfg.Token.Issuer,
		AuthorizationEndpoint:            s.oauthURL(iam.OAuthAuthorizePath),
		TokenEndpoint:                    s.oauthURL(iam.OAuthTokenPath),
		UserInfoEndpoint:                 s.oauthURL(iam.OAuthUserInfoPath),
		RevocationEndpoint:               s.oauthURL(iam.OAuthRevocationPath),
		EndSessionEndpoint:               s.oauthURL(iam.OAuthEndSessionPath),
		JWKSURI:                          s.oauthURL(iam.JWKSPath),
		ScopesSupported:                  scopes,
		ResponseTypesSupported:           []string{"code"},
		ResponseModesSupported:           []string{"query"},
		GrantTypesSupported:              grants,
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: algs,
		TokenEndpointAuthMethods:         authMethods,
		CodeChallengeMethodsSupported:    []string{"S256"},
		ClaimsSupported:                  []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "sid", "azp", "preferred_username", "email", "email_verified", "phone_number", "phone_number_verified", "roles"},
		PromptValuesSupported:            []string{"none", "login", "consent"},
		DPoPSigningAlgValuesSupported:    []string{"ES256"},
		AuthorizationResponseIss:         true,
		RequestParameterSupported:        false,
		RequestURIParameterSupported:     false,
		AuthorizationDetailsTypes:        detailTypes,
		TokenEndpointAuthSigningAlgs:     assertionAlgs,
		BackchannelLogoutSupported:       groups,
	})
}

// handleOAuthAuthorize validates an authorization request, stores it, and
// sends the browser to the SPA to sign in and approve it. Until the client
// and redirect URI are known good, errors answer here (never redirecting to
// an unverified URI); after that they go back to the client.
func (s *Service) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	params, err := oauthParams(r, false)
	if err != nil {
		oauthFail(w, err)
		return
	}
	client, ok, err := s.svc.OAuthClient(r.Context(), params.Get("client_id"))
	if err != nil {
		oauthFail(w, err)
		return
	}
	if !ok {
		oauthFail(w, authflow.NewOAuthError(authflow.OAuthInvalidRequest, "unknown client_id"))
		return
	}
	redirectURI := params.Get("redirect_uri")
	if redirectURI == "" || !slices.Contains(client.RedirectURIs, redirectURI) {
		oauthFail(w, authflow.NewOAuthError(authflow.OAuthInvalidRequest, "redirect_uri is missing or not registered for the client"))
		return
	}
	state := params.Get("state")
	back := func(code, description string) {
		target, err := redirectWith(redirectURI, url.Values{"error": {code}, "error_description": {description}, "state": nonEmpty(state), "iss": {s.cfg.Token.Issuer}})
		if err != nil {
			oauthFail(w, err)
			return
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	}
	a, oerr := s.validateAuthorization(client, redirectURI, params)
	if oerr != nil {
		back(oerr.Code, oerr.Description)
		return
	}
	id, err := s.svc.BeginOAuthAuthorization(r.Context(), a)
	if err != nil {
		serverErr(w, "oauth_authorize", err)
		return
	}
	target, err := redirectWith(s.cfg.Frontend.BaseURL+s.cfg.Frontend.AuthorizePath, url.Values{"authorization": {id}})
	if err != nil {
		serverErr(w, "oauth_authorize", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// validateAuthorization applies RFC 6749 §4.1.1, RFC 7636 and RFC 8707 to a
// request whose client and redirect URI already check out.
func (s *Service) validateAuthorization(client authflow.OAuthClient, redirectURI string, p url.Values) (authflow.OAuthAuthorization, *authflow.OAuthError) {
	fail := func(code, description string) (authflow.OAuthAuthorization, *authflow.OAuthError) {
		return authflow.OAuthAuthorization{}, authflow.NewOAuthError(code, description)
	}
	switch {
	case p.Has("request"):
		return fail(authflow.OAuthRequestNotSupported, "request objects are not supported")
	case p.Has("request_uri"):
		return fail(authflow.OAuthRequestURINotSupported, "request_uri is not supported")
	case p.Get("response_type") != "code":
		return fail(authflow.OAuthUnsupportedResponseType, "response_type must be code")
	case p.Get("response_mode") != "" && p.Get("response_mode") != "query":
		return fail(authflow.OAuthInvalidRequest, "response_mode must be query")
	case !config.OAuthClientAllows(client.OAuthClientConfig, config.GrantAuthorizationCode):
		return fail(authflow.OAuthUnauthorizedClient, "the client may not use the authorization code grant")
	case p.Get("code_challenge_method") != "S256":
		return fail(authflow.OAuthInvalidRequest, "PKCE is required: code_challenge_method must be S256")
	}
	challenge := p.Get("code_challenge")
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(challenge); err != nil || len(raw) != 32 {
		return fail(authflow.OAuthInvalidRequest, "code_challenge must be a base64url SHA-256")
	}
	if client.ThirdParty() {
		return s.validateThirdParty(client, redirectURI, challenge, p)
	}
	resources := p["resource"]
	resource := ""
	switch len(resources) {
	case 0:
	case 1:
		resource = resources[0]
		if !slices.Contains(client.Resources, resource) {
			return fail(authflow.OAuthInvalidTarget, "the client may not request tokens for that resource")
		}
	default:
		return fail(authflow.OAuthInvalidTarget, "request one resource at a time")
	}
	scopes := strings.Fields(p.Get("scope"))
	var allowed []string
	if r, ok := config.FindResourceServer(s.cfg.AuthorizationServer, resource); ok {
		allowed = r.Scopes
	}
	granted := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		switch {
		case slices.Contains(granted, scope):
			continue
		case scope == "offline_access":
			return fail(authflow.OAuthInvalidScope, "offline_access is not available: refresh tokens stand on the sign-in")
		case config.OIDCScope(scope), slices.Contains(allowed, scope):
			granted = append(granted, scope)
		default:
			return fail(authflow.OAuthInvalidScope, "unknown scope "+strconv.Quote(scope))
		}
	}
	return finishAuthorization(client.ID, redirectURI, challenge, granted, resource, p)
}

// validateThirdParty is a group client's request: openid and only the
// scopes it registered, whose group-client scopes name one resource, the
// token's audience (a resource parameter must name it too).
func (s *Service) validateThirdParty(client authflow.OAuthClient, redirectURI, challenge string, p url.Values) (authflow.OAuthAuthorization, *authflow.OAuthError) {
	fail := func(code, description string) (authflow.OAuthAuthorization, *authflow.OAuthError) {
		return authflow.OAuthAuthorization{}, authflow.NewOAuthError(code, description)
	}
	scopes := strings.Fields(p.Get("scope"))
	granted := make([]string, 0, len(scopes))
	resource := ""
	for _, scope := range scopes {
		switch {
		case slices.Contains(granted, scope):
			continue
		case !slices.Contains(client.Group.Scopes, scope):
			return fail(authflow.OAuthInvalidScope, "the client did not register scope "+strconv.Quote(scope))
		}
		if sc, ok := config.FindGroupClientScope(s.cfg.AuthorizationServer, scope); ok {
			if resource != "" && resource != sc.Resource {
				return fail(authflow.OAuthInvalidScope, "request the scopes of one resource at a time")
			}
			resource = sc.Resource
		}
		granted = append(granted, scope)
	}
	if !slices.Contains(granted, "openid") {
		return fail(authflow.OAuthInvalidScope, "scope must include openid")
	}
	switch resources := p["resource"]; {
	case len(resources) > 1:
		return fail(authflow.OAuthInvalidTarget, "request one resource at a time")
	case len(resources) == 1 && resources[0] != resource:
		return fail(authflow.OAuthInvalidTarget, "resource must be the one the requested scopes are for")
	}
	return finishAuthorization(client.ID, redirectURI, challenge, granted, resource, p)
}

// finishAuthorization checks the parameters every authorization request
// shares (prompt, max_age, lengths, dpop_jkt) and builds it.
func finishAuthorization(clientID, redirectURI, challenge string, granted []string, resource string, p url.Values) (authflow.OAuthAuthorization, *authflow.OAuthError) {
	fail := func(code, description string) (authflow.OAuthAuthorization, *authflow.OAuthError) {
		return authflow.OAuthAuthorization{}, authflow.NewOAuthError(code, description)
	}
	prompt := strings.Fields(p.Get("prompt"))
	for _, v := range prompt {
		switch v {
		case "none", "login", "consent", "select_account":
		default:
			return fail(authflow.OAuthInvalidRequest, "unsupported prompt "+strconv.Quote(v))
		}
	}
	if slices.Contains(prompt, "none") && len(prompt) > 1 {
		return fail(authflow.OAuthInvalidRequest, "prompt=none cannot be combined with another value")
	}
	var maxAge *int64
	if raw := p.Get("max_age"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			return fail(authflow.OAuthInvalidRequest, "max_age must be a non-negative integer")
		}
		maxAge = &n
	}
	for _, name := range []string{"state", "nonce", "login_hint"} {
		if len(p.Get(name)) > maxOAuthParamBytes {
			return fail(authflow.OAuthInvalidRequest, name+" is too long")
		}
	}
	jkt := p.Get("dpop_jkt")
	switch {
	case jkt != "" && !jose.ValidThumbprint(jkt):
		return fail(authflow.OAuthInvalidRequest, "dpop_jkt must be a JWK SHA-256 thumbprint")
	case p.Has("authorization_details"):
		return fail(authflow.OAuthInvalidRequest, "authorization_details are granted only by a jwt-bearer capability")
	}
	return authflow.OAuthAuthorization{
		ClientID: clientID, RedirectURI: redirectURI, State: p.Get("state"), Nonce: p.Get("nonce"),
		Scopes: granted, Resource: resource, CodeChallenge: challenge,
		Prompt: prompt, MaxAge: maxAge, LoginHint: p.Get("login_hint"), DPoPJKT: jkt,
	}, nil
}

// handleOAuthToken is the token endpoint: one authenticated (or public)
// client, one grant. A DPoP proof (RFC 9449) binds the tokens to its key. A
// jwt-bearer grant must send one, and so must a user grant (code, refresh,
// token exchange) when SignIn.DPoP is required; otherwise a public client's
// refresh tokens are protected by rotation (RFC 9700 §4.14.2).
func (s *Service) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	s.oauthCORS(w, r)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	params, err := oauthParams(r, true)
	if err != nil {
		oauthFail(w, err)
		return
	}
	if s.remoteAssertion(params, r) {
		s.handleRemoteAssertion(w, r, params)
		return
	}
	client, oerr := s.authenticateOAuthClient(r, params)
	if oerr != nil {
		oauthClientFail(w, r, oerr)
		return
	}
	grant := config.OAuthGrantType(params.Get("grant_type"))
	switch grant {
	case "":
		oauthFail(w, authflow.NewOAuthError(authflow.OAuthInvalidRequest, "grant_type is required"))
		return
	case config.GrantAuthorizationCode, config.GrantRefreshToken, config.GrantTokenExchange, config.GrantClientCredentials, config.GrantJWTBearer:
	default:
		oauthFail(w, authflow.NewOAuthError(authflow.OAuthUnsupportedGrantType, "unsupported grant_type"))
		return
	}
	if !config.OAuthClientAllows(client.OAuthClientConfig, grant) {
		oauthFail(w, authflow.NewOAuthError(authflow.OAuthUnauthorizedClient, "the client may not use this grant"))
		return
	}
	if len(params["resource"]) > 1 {
		oauthFail(w, authflow.NewOAuthError(authflow.OAuthInvalidTarget, "request one resource at a time"))
		return
	}
	if params.Has("authorization_details") {
		oauthFail(w, authflow.NewOAuthError(authflow.OAuthInvalidRequest, "authorization_details are granted only by a jwt-bearer capability"))
		return
	}
	jkt, err := s.oauthTokenDPoP(r, grant)
	if err != nil {
		oauthFail(w, err)
		return
	}
	var tokens authflow.OAuthTokens
	switch grant {
	case config.GrantAuthorizationCode:
		tokens, err = s.svc.ExchangeOAuthCode(r.Context(), authflow.OAuthCodeExchange{
			ClientID: client.ID, Code: params.Get("code"), RedirectURI: params.Get("redirect_uri"),
			CodeVerifier: params.Get("code_verifier"), Resource: params.Get("resource"), JKT: jkt,
		})
	case config.GrantRefreshToken:
		tokens, err = s.svc.RefreshOAuthTokens(r.Context(), authflow.OAuthRefresh{
			ClientID: client.ID, RefreshToken: params.Get("refresh_token"), Scopes: scopeParam(params),
			Resource: params.Get("resource"), JKT: jkt,
		})
	case config.GrantTokenExchange:
		tokens, err = s.svc.ExchangeOAuthToken(r.Context(), authflow.OAuthTokenExchange{
			ClientID: client.ID, SubjectToken: params.Get("subject_token"), SubjectTokenType: params.Get("subject_token_type"),
			RequestedTokenType: params.Get("requested_token_type"), Resource: params.Get("resource"),
			Scopes: strings.Fields(params.Get("scope")), JKT: jkt,
		})
	case config.GrantClientCredentials:
		tokens, err = s.svc.OAuthClientCredentials(r.Context(), authflow.OAuthClientCredentials{
			ClientID: client.ID, Resource: params.Get("resource"), Scopes: strings.Fields(params.Get("scope")), JKT: jkt,
		})
	case config.GrantJWTBearer:
		tokens, err = s.svc.OAuthJWTBearer(r.Context(), authflow.OAuthJWTBearer{
			ClientID: client.ID, Assertion: params.Get("assertion"), Resource: params.Get("resource"),
			Scopes: strings.Fields(params.Get("scope")), JKT: jkt,
		})
	}
	if err != nil {
		oauthFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

// oauthTokenDPoP verifies the token request's DPoP proof (no ath at the
// token endpoint) and returns its key's thumbprint: "" without one, which a
// user grant may omit unless SignIn.DPoP is required (the jwt-bearer grant
// refuses it; client credentials never need one).
func (s *Service) oauthTokenDPoP(r *http.Request, grant config.OAuthGrantType) (string, error) {
	if len(r.Header.Values("DPoP")) == 0 {
		if grant != config.GrantClientCredentials && grant != config.GrantJWTBearer && s.cfg.SignIn.DPoP == config.DPoPRequired {
			return "", authflow.NewOAuthError(authflow.OAuthInvalidDPoPProof, "a DPoP proof is required")
		}
		return "", nil
	}
	jkt, err := dpop.Verify(r, dpop.Check{URL: s.oauthURL(iam.OAuthTokenPath), Replay: s.replays.Claim})
	switch {
	case errors.Is(err, dpop.ErrReplayUnavailable):
		return "", err
	case err != nil:
		return "", authflow.NewOAuthError(authflow.OAuthInvalidDPoPProof, "the DPoP proof is invalid or already used")
	}
	return jkt, nil
}

// scopeParam is the scope parameter's scopes; nil when it is absent.
func scopeParam(params url.Values) []string {
	if !params.Has("scope") {
		return nil
	}
	return append([]string{}, strings.Fields(params.Get("scope"))...)
}

// handleOAuthRevoke is RFC 7009 token revocation for an authenticated (or
// public) client: a refresh token ends its family. It answers 200 for any
// token, revoked or not.
func (s *Service) handleOAuthRevoke(w http.ResponseWriter, r *http.Request) {
	s.oauthCORS(w, r)
	w.Header().Set("Cache-Control", "no-store")
	params, err := oauthParams(r, true)
	if err != nil {
		oauthFail(w, err)
		return
	}
	client, oerr := s.authenticateOAuthClient(r, params)
	if oerr != nil {
		oauthClientFail(w, r, oerr)
		return
	}
	if params.Get("token") == "" {
		oauthFail(w, authflow.NewOAuthError(authflow.OAuthInvalidRequest, "token is required"))
		return
	}
	if err := s.svc.RevokeOAuthToken(r.Context(), client.ID, params.Get("token")); err != nil {
		oauthFail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// oauthClientFail answers a failed client authentication; one that used
// the Authorization header gets its Basic challenge (RFC 6749 §5.2).
func oauthClientFail(w http.ResponseWriter, r *http.Request, oerr *authflow.OAuthError) {
	if _, _, basic := r.BasicAuth(); basic && oerr.Code == authflow.OAuthInvalidClient {
		w.Header().Set("WWW-Authenticate", `Basic realm="authkit"`)
	}
	oauthFail(w, oerr)
}

// authenticateOAuthClient applies RFC 6749 §2.3: a confidential client
// authenticates with its secret (Basic or in the body, exactly one way); a
// public client names itself and sends no secret. A group client uses the
// one method it registered: client_secret_basic, private_key_jwt (RFC 7523
// §2.2) or none.
func (s *Service) authenticateOAuthClient(r *http.Request, params url.Values) (authflow.OAuthClient, *authflow.OAuthError) {
	invalid := &authflow.OAuthError{Code: authflow.OAuthInvalidClient, Description: "client authentication failed", Status: http.StatusUnauthorized}
	id, secretValue, basic := r.BasicAuth()
	if params.Has("client_assertion") || params.Has("client_assertion_type") {
		if basic || params.Has("client_secret") || params.Get("client_assertion_type") != authflow.ClientAssertionType {
			return authflow.OAuthClient{}, invalid
		}
		_, unverified, ok := jose.Unverified(params.Get("client_assertion"))
		id = jose.String(unverified, "iss")
		if !ok || id == "" || params.Has("client_id") && params.Get("client_id") != id {
			return authflow.OAuthClient{}, invalid
		}
		client, found, err := s.svc.OAuthClient(r.Context(), id)
		if err != nil || !found {
			return authflow.OAuthClient{}, invalid
		}
		if err := s.svc.AuthenticateClientAssertion(r.Context(), client, params.Get("client_assertion")); err != nil {
			return authflow.OAuthClient{}, invalid
		}
		return client, nil
	}
	if basic {
		var err1, err2 error
		id, err1 = url.QueryUnescape(id)
		secretValue, err2 = url.QueryUnescape(secretValue)
		if err1 != nil || err2 != nil || params.Has("client_secret") || (params.Has("client_id") && params.Get("client_id") != id) {
			return authflow.OAuthClient{}, invalid
		}
	} else {
		id, secretValue = params.Get("client_id"), params.Get("client_secret")
	}
	client, ok, err := s.svc.OAuthClient(r.Context(), id)
	switch {
	case err != nil || !ok:
		return authflow.OAuthClient{}, invalid
	case client.ThirdParty():
		switch client.Group.AuthMethod {
		case iam.OAuthClientSecretBasic:
			if !basic || secretValue == "" || !secret.Equal(secret.Hash(secretValue), client.SecretSHA256) {
				return authflow.OAuthClient{}, invalid
			}
		case iam.OAuthClientNone:
			if basic || secretValue != "" {
				return authflow.OAuthClient{}, invalid
			}
		default:
			return authflow.OAuthClient{}, invalid
		}
	case config.OAuthClientConfidential(client.OAuthClientConfig):
		if secretValue == "" || !secret.Equal(secret.Hash(secretValue), client.SecretSHA256) {
			return authflow.OAuthClient{}, invalid
		}
	case secretValue != "":
		return authflow.OAuthClient{}, invalid
	}
	return client, nil
}

// handleOAuthUserInfo answers the userinfo endpoint for an access token
// this server minted with the openid scope: a bearer token, or a DPoP-bound
// one with a fresh proof of its key.
func (s *Service) handleOAuthUserInfo(w http.ResponseWriter, r *http.Request) {
	s.oauthCORS(w, r)
	w.Header().Set("Cache-Control", "no-store")
	token, isDPoP := jose.RequestToken(r)
	scheme := "Bearer"
	if isDPoP {
		scheme = "DPoP"
	}
	refuse := func(code, description string, status int) {
		w.Header().Set("WWW-Authenticate", scheme+` error="`+code+`"`)
		oauthFail(w, &authflow.OAuthError{Code: code, Description: description, Status: status})
	}
	if token == "" {
		refuse(authflow.OAuthInvalidToken, "an access token is required", http.StatusUnauthorized)
		return
	}
	jkt := ""
	if isDPoP {
		var err error
		jkt, err = dpop.Verify(r, dpop.Check{URL: s.oauthURL(iam.OAuthUserInfoPath), AccessToken: token, Replay: s.replays.Claim})
		switch {
		case errors.Is(err, dpop.ErrReplayUnavailable):
			oauthFail(w, err)
			return
		case err != nil:
			refuse(authflow.OAuthInvalidDPoPProof, "the DPoP proof is invalid or already used", http.StatusUnauthorized)
			return
		}
	}
	claims, err := s.svc.OAuthUserInfo(r.Context(), token, jkt)
	if err != nil {
		var oe *authflow.OAuthError
		if errors.As(err, &oe) {
			status := oe.Status
			if status == 0 {
				status = http.StatusUnauthorized
			}
			refuse(oe.Code, oe.Description, status)
			return
		}
		oauthFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

// handleOAuthEndSession is OIDC RP-Initiated Logout: it ends the sign-in
// the ID token names, then returns the browser to the client's registered
// post-logout URI, or to the frontend.
func (s *Service) handleOAuthEndSession(w http.ResponseWriter, r *http.Request) {
	params, err := oauthParams(r, false)
	if err != nil {
		oauthFail(w, err)
		return
	}
	target, err := s.svc.EndOAuthSession(r.Context(), authflow.OAuthEndSession{
		IDTokenHint: params.Get("id_token_hint"), ClientID: params.Get("client_id"),
		PostLogoutRedirectURI: params.Get("post_logout_redirect_uri"), State: params.Get("state"),
	})
	if err != nil {
		oauthFail(w, err)
		return
	}
	if target == "" {
		target = s.cfg.Frontend.BaseURL
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// handleOAuthPreflight answers CORS preflights for the endpoints a browser
// client calls directly.
func (s *Service) handleOAuthPreflight(w http.ResponseWriter, r *http.Request) {
	if s.oauthCORS(w, r) {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, DPoP")
		w.Header().Set("Access-Control-Max-Age", "600")
	}
	w.WriteHeader(http.StatusNoContent)
}

// oauthCORS allows a registered browser client's origin (one of its Origins
// or its redirect URIs') to read the answer. No credentials: these endpoints take
// none from cookies.
func (s *Service) oauthCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	w.Header().Add("Vary", "Origin")
	if origin == "" || !s.oauthOrigin(r.Context(), origin) {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Expose-Headers", "DPoP-Nonce, WWW-Authenticate")
	return true
}

// remoteAssertion reports a jwt-bearer request with no client: a trusted
// application's assertion for a resource server (RFC 7521 §4.1 needs no
// client authentication).
func (s *Service) remoteAssertion(params url.Values, r *http.Request) bool {
	_, _, basic := r.BasicAuth()
	return s.cfg.Resource.Enabled() && config.OAuthGrantType(params.Get("grant_type")) == config.GrantJWTBearer &&
		!params.Has("client_id") && !params.Has("client_secret") && !basic
}

// handleRemoteAssertion redeems a trusted application's RFC 7523 assertion
// for an access token to Config.Resource.ID, bound by the request's DPoP
// proof when it sends one.
func (s *Service) handleRemoteAssertion(w http.ResponseWriter, r *http.Request, params url.Values) {
	if len(params["resource"]) > 1 || params.Has("authorization_details") {
		oauthFail(w, authflow.NewOAuthError(authflow.OAuthInvalidRequest, "one resource, and no authorization_details"))
		return
	}
	jkt, err := s.oauthTokenDPoP(r, config.GrantJWTBearer)
	if err != nil {
		oauthFail(w, err)
		return
	}
	tokens, err := s.svc.OAuthRemoteAssertion(r.Context(), authflow.OAuthJWTBearer{
		Assertion: params.Get("assertion"), Resource: params.Get("resource"), Scopes: strings.Fields(params.Get("scope")), JKT: jkt,
	})
	if err != nil {
		oauthFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

// oauthOrigin reports whether origin may call the token endpoint: a
// client's, or any when this deployment is a resource server, whose trusted
// applications' frontends redeem assertions there. The endpoint takes no
// cookies.
func (s *Service) oauthOrigin(ctx context.Context, origin string) bool {
	if s.cfg.Resource.Enabled() {
		return true
	}
	if ok, err := s.svc.OAuthClientOrigin(ctx, origin); err == nil && ok {
		return true
	}
	for _, c := range s.cfg.AuthorizationServer.Clients {
		if slices.Contains(c.Origins, origin) {
			return true
		}
		for _, uri := range c.RedirectURIs {
			if u, err := url.Parse(uri); err == nil && u.Scheme+"://"+u.Host == origin {
				return true
			}
		}
	}
	return false
}

// oauthParams reads a protocol request's parameters. The token endpoint
// takes only a form body (bodyOnly); the browser endpoints take the query or
// a form POST. A parameter sent twice is invalid (RFC 6749 §3.1), except
// resource, which RFC 8707 lets repeat.
func oauthParams(r *http.Request, bodyOnly bool) (url.Values, error) {
	invalid := func(description string) error {
		return authflow.NewOAuthError(authflow.OAuthInvalidRequest, description)
	}
	var params url.Values
	switch r.Method {
	case http.MethodPost:
		mediaType, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
		if !strings.EqualFold(strings.TrimSpace(mediaType), "application/x-www-form-urlencoded") {
			return nil, invalid("the body must be application/x-www-form-urlencoded")
		}
		if bodyOnly && r.URL.RawQuery != "" {
			return nil, invalid("parameters must be sent in the body")
		}
		r.Body = http.MaxBytesReader(nil, r.Body, maxOAuthFormBytes)
		if err := r.ParseForm(); err != nil {
			return nil, invalid("the form body cannot be parsed")
		}
		params = r.PostForm
		if !bodyOnly {
			for k, vs := range r.URL.Query() {
				params[k] = append(params[k], vs...)
			}
		}
	case http.MethodGet:
		if bodyOnly {
			return nil, invalid("use POST")
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return nil, invalid("the query cannot be parsed")
		}
		params = q
	default:
		return nil, invalid("unsupported method")
	}
	for k, vs := range params {
		if len(vs) > 1 && k != "resource" {
			return nil, invalid(k + " is repeated")
		}
	}
	return params, nil
}

// oauthFail answers an OAuth error ({error, error_description}, and reason
// when set); any other error is a server_error, logged.
func oauthFail(w http.ResponseWriter, err error) {
	var oe *authflow.OAuthError
	if !errors.As(err, &oe) {
		if e := errmodel.As(err); e != nil && e.Status() < 500 {
			oe = authflow.NewOAuthError(authflow.OAuthInvalidRequest, e.Error())
		} else {
			slog.Default().Error("authkit: oauth request failed", slog.String("error", errorString(err)))
			oe = &authflow.OAuthError{Code: authflow.OAuthServerError, Description: "the request could not be completed", Status: http.StatusInternalServerError}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(oe.HTTPStatus())
	body := map[string]string{"error": oe.Code, "error_description": oe.Description}
	if oe.Reason != "" {
		body["reason"] = oe.Reason
	}
	_ = json.NewEncoder(w).Encode(body)
}

// redirectWith appends params to a URI, keeping its own query.
func redirectWith(base string, params url.Values) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			if v != "" {
				q.Add(k, v)
			}
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func nonEmpty(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}
