package httpapi

// The authorization server's protocol endpoints (#430): issuer metadata
// (RFC 8414, OIDC Discovery), authorize (RFC 6749 §4.1 with RFC 7636 PKCE and
// RFC 8707 resource indicators), token, userinfo and RP-initiated logout.
// They answer OAuth's own error format, not AuthKit's envelope. Validation
// that does not need state lives here; the engine owns requests, codes and
// tokens.

import (
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
	scopes := []string{"openid", "profile", "email"}
	for _, r := range as.Resources {
		for _, scope := range r.Scopes {
			if !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
	}
	grants := []string{}
	authMethods := []string{}
	for _, c := range as.Clients {
		for _, g := range c.GrantTypes {
			if !slices.Contains(grants, string(g)) {
				grants = append(grants, string(g))
			}
		}
		method := "none"
		if config.OAuthClientConfidential(c) {
			method = "client_secret_basic"
		}
		if !slices.Contains(authMethods, method) {
			authMethods = append(authMethods, method)
		}
		if method == "client_secret_basic" && !slices.Contains(authMethods, "client_secret_post") {
			authMethods = append(authMethods, "client_secret_post")
		}
	}
	algs := []string{}
	for _, k := range s.svc.JWKS().Keys {
		if k.Alg != "" && !slices.Contains(algs, k.Alg) {
			algs = append(algs, k.Alg)
		}
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, OAuthServerMetadata{
		Issuer:                           s.cfg.Token.Issuer,
		AuthorizationEndpoint:            s.oauthURL(iam.OAuthAuthorizePath),
		TokenEndpoint:                    s.oauthURL(iam.OAuthTokenPath),
		UserInfoEndpoint:                 s.oauthURL(iam.OAuthUserInfoPath),
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
		ClaimsSupported:                  []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "sid", "azp", "preferred_username", "email", "email_verified", "roles"},
		PromptValuesSupported:            []string{"none", "login"},
		AuthorizationResponseIss:         true,
		RequestParameterSupported:        false,
		RequestURIParameterSupported:     false,
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
	client, ok := config.FindOAuthClient(s.cfg.AuthorizationServer, params.Get("client_id"))
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
func (s *Service) validateAuthorization(client config.OAuthClientConfig, redirectURI string, p url.Values) (authflow.OAuthAuthorization, *authflow.OAuthError) {
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
	case !config.OAuthClientAllows(client, config.GrantAuthorizationCode):
		return fail(authflow.OAuthUnauthorizedClient, "the client may not use the authorization code grant")
	case p.Get("code_challenge_method") != "S256":
		return fail(authflow.OAuthInvalidRequest, "PKCE is required: code_challenge_method must be S256")
	}
	challenge := p.Get("code_challenge")
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(challenge); err != nil || len(raw) != 32 {
		return fail(authflow.OAuthInvalidRequest, "code_challenge must be a base64url SHA-256")
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
			return fail(authflow.OAuthInvalidScope, "offline_access is not available to this client")
		case config.OIDCScope(scope), slices.Contains(allowed, scope):
			granted = append(granted, scope)
		default:
			return fail(authflow.OAuthInvalidScope, "unknown scope "+strconv.Quote(scope))
		}
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
	return authflow.OAuthAuthorization{
		ClientID: client.ID, RedirectURI: redirectURI, State: p.Get("state"), Nonce: p.Get("nonce"),
		Scopes: granted, Resource: resource, CodeChallenge: challenge,
		Prompt: prompt, MaxAge: maxAge, LoginHint: p.Get("login_hint"),
	}, nil
}

// handleOAuthToken is the token endpoint: one authenticated (or public)
// client, one grant.
func (s *Service) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	s.oauthCORS(w, r)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	params, err := oauthParams(r, true)
	if err != nil {
		oauthFail(w, err)
		return
	}
	client, oerr := s.authenticateOAuthClient(r, params)
	if oerr != nil {
		oauthFail(w, oerr)
		return
	}
	switch grant := config.OAuthGrantType(params.Get("grant_type")); grant {
	case "":
		oauthFail(w, authflow.NewOAuthError(authflow.OAuthInvalidRequest, "grant_type is required"))
	case config.GrantAuthorizationCode:
		if !config.OAuthClientAllows(client, grant) {
			oauthFail(w, authflow.NewOAuthError(authflow.OAuthUnauthorizedClient, "the client may not use this grant"))
			return
		}
		if len(params["resource"]) > 1 {
			oauthFail(w, authflow.NewOAuthError(authflow.OAuthInvalidTarget, "request one resource at a time"))
			return
		}
		tokens, err := s.svc.ExchangeOAuthCode(r.Context(), authflow.OAuthCodeExchange{
			ClientID: client.ID, Code: params.Get("code"), RedirectURI: params.Get("redirect_uri"),
			CodeVerifier: params.Get("code_verifier"), Resource: params.Get("resource"),
		})
		if err != nil {
			oauthFail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, tokens)
	default:
		oauthFail(w, authflow.NewOAuthError(authflow.OAuthUnsupportedGrantType, "unsupported grant_type"))
	}
}

// authenticateOAuthClient applies RFC 6749 §2.3: a confidential client
// authenticates with its secret (Basic or in the body, exactly one way); a
// public client names itself and sends no secret.
func (s *Service) authenticateOAuthClient(r *http.Request, params url.Values) (config.OAuthClientConfig, *authflow.OAuthError) {
	invalid := &authflow.OAuthError{Code: authflow.OAuthInvalidClient, Description: "client authentication failed", Status: http.StatusUnauthorized}
	id, secretValue, basic := r.BasicAuth()
	if basic {
		var err1, err2 error
		id, err1 = url.QueryUnescape(id)
		secretValue, err2 = url.QueryUnescape(secretValue)
		if err1 != nil || err2 != nil || params.Has("client_secret") || (params.Has("client_id") && params.Get("client_id") != id) {
			return config.OAuthClientConfig{}, invalid
		}
	} else {
		id, secretValue = params.Get("client_id"), params.Get("client_secret")
	}
	client, ok := config.FindOAuthClient(s.cfg.AuthorizationServer, id)
	switch {
	case !ok:
		return config.OAuthClientConfig{}, invalid
	case config.OAuthClientConfidential(client):
		if secretValue == "" || !secret.Equal(secret.Hash(secretValue), client.SecretSHA256) {
			return config.OAuthClientConfig{}, invalid
		}
	case secretValue != "":
		return config.OAuthClientConfig{}, invalid
	}
	return client, nil
}

// handleOAuthUserInfo answers the userinfo endpoint for a bearer access
// token this server minted with the openid scope.
func (s *Service) handleOAuthUserInfo(w http.ResponseWriter, r *http.Request) {
	s.oauthCORS(w, r)
	w.Header().Set("Cache-Control", "no-store")
	token, dpop := jose.RequestToken(r)
	if token == "" || dpop {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oauthFail(w, &authflow.OAuthError{Code: authflow.OAuthInvalidToken, Description: "a Bearer access token is required", Status: http.StatusUnauthorized})
		return
	}
	claims, err := s.svc.OAuthUserInfo(r.Context(), token)
	if err != nil {
		var oe *authflow.OAuthError
		if errors.As(err, &oe) {
			if oe.Status == 0 {
				oe = &authflow.OAuthError{Code: oe.Code, Description: oe.Description, Status: http.StatusUnauthorized}
			}
			w.Header().Set("WWW-Authenticate", `Bearer error="`+oe.Code+`"`)
			err = oe
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

// oauthCORS allows a registered browser client's origin (that of one of its
// redirect URIs) to read the answer. No credentials: these endpoints take
// none from cookies.
func (s *Service) oauthCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	w.Header().Add("Vary", "Origin")
	if origin == "" || !s.oauthOrigin(origin) {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Expose-Headers", "DPoP-Nonce, WWW-Authenticate")
	return true
}

func (s *Service) oauthOrigin(origin string) bool {
	for _, c := range s.cfg.AuthorizationServer.Clients {
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

// oauthFail answers an OAuth error ({error, error_description}); any other
// error is a server_error, logged.
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
	_ = json.NewEncoder(w).Encode(map[string]string{"error": oe.Code, "error_description": oe.Description})
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
