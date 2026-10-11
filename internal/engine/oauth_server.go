package engine

// The OAuth 2.0 authorization server and OpenID provider (#430). The HTTP
// layer validates protocol requests against the registered clients; the
// engine owns the state (pending authorization requests and codes, in the
// ephemeral store) and every token it mints: RFC 9068 access tokens for a
// registered resource and OIDC ID tokens. Each grant re-checks the user and
// the sign-in it stands on.

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/secret"
)

const (
	keyOAuthAuthorization = "oauth:authz:" // +hash of the request id
	oauthAuthorizationTTL = 10 * time.Minute
	keyOAuthCode          = "oauth:code:" // +hash of the code
	oauthCodeTTL          = 60 * time.Second
	oauthIDTokenTTL       = 10 * time.Minute
	// idTokenType is the ID token's JOSE typ; no other token is signed with it.
	idTokenType = "JWT"
)

// BeginOAuthAuthorization stores a validated authorization request for its
// user and returns its id: a secret the SPA approves or declines it by.
func (s *Engine) BeginOAuthAuthorization(ctx context.Context, a authflow.OAuthAuthorization) (string, error) {
	now := s.nowTime()
	a.CreatedAt, a.ExpiresAt = now.UTC(), now.Add(oauthAuthorizationTTL).UTC()
	id := secret.Token(32)
	if err := s.ephemSetJSON(ctx, keyOAuthAuthorization+secret.Hash(id), a, oauthAuthorizationTTL); err != nil {
		return "", err
	}
	return id, nil
}

// OAuthAuthorization reads a pending authorization request.
func (s *Engine) OAuthAuthorization(ctx context.Context, id string) (authflow.OAuthAuthorization, error) {
	a, _, err := s.oauthAuthorization(ctx, id)
	return a, err
}

func (s *Engine) oauthAuthorization(ctx context.Context, id string) (authflow.OAuthAuthorization, []byte, error) {
	var a authflow.OAuthAuthorization
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 128 {
		return a, nil, errmodel.E(errmodel.CodeAuthorizationRequestNotFound)
	}
	raw, ok, err := s.ephemReadJSON(ctx, keyOAuthAuthorization+secret.Hash(id), &a)
	switch {
	case err != nil:
		return a, nil, err
	case !ok:
		return a, nil, errmodel.E(errmodel.CodeAuthorizationRequestNotFound)
	}
	return a, raw, nil
}

// ApproveOAuthAuthorization answers a pending request for the signed-in user
// of sessionID: it issues a one-time authorization code and returns the
// client redirect carrying it. A request asking for a fresh sign-in
// (prompt=login, max_age) that this one does not meet is StepUpRequired,
// and stays pending for the retry.
func (s *Engine) ApproveOAuthAuthorization(ctx context.Context, userID, sessionID, id string) (string, error) {
	a, raw, err := s.oauthAuthorization(ctx, id)
	if err != nil {
		return "", err
	}
	client, ok := config.FindOAuthClient(s.cfg.AuthorizationServer, a.ClientID)
	if !ok {
		return "", errmodel.E(errmodel.CodeAuthorizationRequestNotFound)
	}
	if err := s.requireOAuthSignIn(ctx, userID, sessionID); err != nil {
		return "", err
	}
	if err := s.requireAcceptedAgreements(ctx, userID, client.Agreements); err != nil {
		return "", err
	}
	authTime, amr, acr, err := s.sessionAssurance(ctx, userID, sessionID)
	if err != nil {
		return "", err
	}
	// Freshness is measured from the request, so a step-up taken for it
	// satisfies max_age=0 however long the approval takes.
	stale := slices.Contains(a.Prompt, "login") && authTime < a.CreatedAt.Unix()
	if stale || a.MaxAge != nil && authTime < a.CreatedAt.Unix()-*a.MaxAge {
		// Carries the account's step-up methods, for the SPA's dialog.
		return "", s.StepUpRequired(ctx, userID)
	}
	claimed, err := s.ephemeral.CompareAndConsume(ctx, keyOAuthAuthorization+secret.Hash(strings.TrimSpace(id)), raw)
	if err != nil {
		return "", err
	}
	if !claimed {
		return "", errmodel.E(errmodel.CodeAuthorizationRequestNotFound)
	}
	code := secret.Token(32)
	grant := authflow.OAuthGrant{
		ClientID: a.ClientID, RedirectURI: a.RedirectURI, CodeChallenge: a.CodeChallenge,
		Nonce: a.Nonce, Scopes: a.Scopes, Resource: a.Resource,
		UserID: userID, SessionID: sessionID, AuthTime: authTime, AMR: amr, ACR: acr, DPoPJKT: a.DPoPJKT,
	}
	if err := s.ephemSetJSON(ctx, keyOAuthCode+secret.Hash(code), grant, oauthCodeTTL); err != nil {
		return "", err
	}
	s.oauthAudit(ctx, "oauth_authorization_approved", userID, map[string]string{"client_id": a.ClientID, "session_id": sessionID})
	return oauthRedirect(a.RedirectURI, url.Values{"code": {code}, "state": optional(a.State), "iss": {s.cfg.Token.Issuer}})
}

// DeclineOAuthAuthorization ends a pending request without a code and
// returns the client redirect carrying the error: access_denied when the
// user refused, login_required or interaction_required when prompt=none
// could not be met without the user.
func (s *Engine) DeclineOAuthAuthorization(ctx context.Context, id, code string) (string, error) {
	switch code {
	case authflow.OAuthAccessDenied, authflow.OAuthLoginRequired, authflow.OAuthInteractionRequired:
	default:
		return "", errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("error"))
	}
	var a authflow.OAuthAuthorization
	ok, err := s.ephemConsumeJSON(ctx, keyOAuthAuthorization+secret.Hash(strings.TrimSpace(id)), &a)
	switch {
	case err != nil:
		return "", err
	case !ok:
		return "", errmodel.E(errmodel.CodeAuthorizationRequestNotFound)
	}
	return oauthRedirect(a.RedirectURI, url.Values{"error": {code}, "state": optional(a.State), "iss": {s.cfg.Token.Issuer}})
}

// ExchangeOAuthCode redeems an authorization code once (RFC 6749 §4.1.3,
// RFC 7636 §4.6): the client, redirect URI and PKCE verifier must match the
// approval, and the user's sign-in must still stand.
func (s *Engine) ExchangeOAuthCode(ctx context.Context, in authflow.OAuthCodeExchange) (authflow.OAuthTokens, error) {
	var g authflow.OAuthGrant
	ok, err := s.ephemConsumeJSON(ctx, keyOAuthCode+secret.Hash(in.Code), &g)
	switch {
	case err != nil:
		return authflow.OAuthTokens{}, err
	case !ok:
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidGrant, "the authorization code is invalid, expired or already used")
	case !secret.Equal(g.ClientID, in.ClientID):
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidGrant, "the authorization code was issued to another client")
	case g.RedirectURI != in.RedirectURI:
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidGrant, "redirect_uri does not match the authorization request")
	case !pkceVerifies(in.CodeVerifier, g.CodeChallenge):
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidGrant, "code_verifier does not match the code_challenge")
	case in.Resource != "" && in.Resource != g.Resource:
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidTarget, "resource does not match the authorization request")
	case g.DPoPJKT != "" && !secret.Equal(g.DPoPJKT, in.JKT):
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidDPoPProof, "the DPoP key is not the one the authorization request named")
	}
	client, ok := config.FindOAuthClient(s.cfg.AuthorizationServer, g.ClientID)
	if !ok {
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidGrant, "the client is no longer registered")
	}
	if err := s.oauthSignInStands(ctx, g.UserID, g.SessionID, "the sign-in the code was issued for has ended"); err != nil {
		return authflow.OAuthTokens{}, err
	}
	m := oauthMint{
		client: client, userID: g.UserID, sessionID: g.SessionID, scopes: g.Scopes, resource: g.Resource,
		nonce: g.Nonce, authTime: g.AuthTime, amr: g.AMR, acr: g.ACR, jkt: in.JKT,
	}
	tokens, err := s.mintOAuthTokens(ctx, m)
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	if config.OAuthClientAllows(client, config.GrantRefreshToken) {
		if tokens.RefreshToken, err = s.startOAuthRefreshFamily(ctx, m); err != nil {
			return authflow.OAuthTokens{}, err
		}
	}
	s.oauthAudit(ctx, "oauth_code_exchanged", g.UserID, map[string]string{"client_id": g.ClientID, "session_id": g.SessionID})
	return tokens, nil
}

// oauthSignInStands is requireOAuthSignIn answering invalid_grant (with
// description) once the user or sign-in is gone; a store failure stays an
// error.
func (s *Engine) oauthSignInStands(ctx context.Context, userID, sessionID, description string) error {
	err := s.requireOAuthSignIn(ctx, userID, sessionID)
	if err != nil && (errors.Is(err, iam.ErrSessionRevoked) || errors.Is(err, iam.ErrUserNotFound) || errmodel.As(err) != nil && errmodel.As(err).Status() < 500) {
		return authflow.NewOAuthError(authflow.OAuthInvalidGrant, description)
	}
	return err
}

// OAuthUserInfo answers the userinfo endpoint (OIDC Core §5.3) for one of
// this server's access tokens granted the openid scope. jkt is the
// request's proven DPoP key: a DPoP-bound token needs its own, and a bearer
// token none.
func (s *Engine) OAuthUserInfo(ctx context.Context, accessToken, jkt string) (map[string]any, error) {
	claims, err := s.verifyOwnToken(accessToken, jose.ResourceAccessTokenType)
	if err != nil {
		return nil, authflow.NewOAuthError(authflow.OAuthInvalidToken, "the access token is invalid")
	}
	if member, bound, err := jose.Confirmation(accessToken); err != nil || (member != "" && member != jose.JWKThumbprintMember) || bound != jkt {
		return nil, authflow.NewOAuthError(authflow.OAuthInvalidToken, "the request does not prove the access token's DPoP key")
	}
	exp, ok := jose.Time(claims, "exp")
	if !ok || !s.nowTime().Before(exp) {
		return nil, authflow.NewOAuthError(authflow.OAuthInvalidToken, "the access token has expired")
	}
	scopes := strings.Fields(jose.String(claims, "scope"))
	if !slices.Contains(scopes, "openid") {
		return nil, &authflow.OAuthError{Code: "insufficient_scope", Description: "the access token was not granted the openid scope", Status: 403}
	}
	userID, sessionID := jose.String(claims, "sub"), jose.String(claims, "sid")
	if err := s.requireOAuthSignIn(ctx, userID, sessionID); err != nil {
		return nil, authflow.NewOAuthError(authflow.OAuthInvalidToken, "the sign-in the access token was issued for has ended")
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return nil, authflow.NewOAuthError(authflow.OAuthInvalidToken, "the user no longer exists")
	}
	out := map[string]any{"sub": userID}
	s.addProfileClaims(ctx, out, u, scopes)
	return out, nil
}

// EndOAuthSession ends the sign-in an ID token names (OIDC RP-Initiated
// Logout) and returns where to send the browser: the client's registered
// post-logout redirect, with state, or "" when there is none.
func (s *Engine) EndOAuthSession(ctx context.Context, in authflow.OAuthEndSession) (string, error) {
	clientID := in.ClientID
	var userID, sessionID string
	if in.IDTokenHint != "" {
		// Only an ID token: an access token a resource server holds names the
		// same sub and sid, and must not end the user's sign-in.
		claims, err := s.verifyOwnToken(in.IDTokenHint, idTokenType)
		azp := jose.String(claims, "azp")
		audiences := jose.Audiences(claims)
		_, registered := config.FindOAuthClient(s.cfg.AuthorizationServer, azp)
		if err != nil || !registered || len(audiences) != 1 || audiences[0] != azp {
			return "", authflow.NewOAuthError(authflow.OAuthInvalidRequest, "id_token_hint is not an ID token this server issued")
		}
		if clientID == "" {
			clientID = azp
		}
		if clientID != azp {
			return "", authflow.NewOAuthError(authflow.OAuthInvalidRequest, "id_token_hint was issued to another client")
		}
		userID, sessionID = jose.String(claims, "sub"), jose.String(claims, "sid")
	}
	redirect := ""
	if in.PostLogoutRedirectURI != "" {
		client, ok := config.FindOAuthClient(s.cfg.AuthorizationServer, clientID)
		if !ok || !slices.Contains(client.PostLogoutRedirectURIs, in.PostLogoutRedirectURI) {
			return "", authflow.NewOAuthError(authflow.OAuthInvalidRequest, "post_logout_redirect_uri is not registered for the client")
		}
		var err error
		if redirect, err = oauthRedirect(in.PostLogoutRedirectURI, url.Values{"state": optional(in.State)}); err != nil {
			return "", err
		}
	}
	if userID != "" && sessionID != "" {
		if err := s.RevokeSessionByIDForUser(ctx, userID, sessionID); err != nil {
			return "", err
		}
		s.oauthAudit(ctx, "oauth_session_ended", userID, map[string]string{"client_id": clientID, "session_id": sessionID})
	}
	return redirect, nil
}

// requireOAuthSignIn refuses a user who is not live, and a session that no
// longer stands: every grant on a sign-in needs both.
func (s *Engine) requireOAuthSignIn(ctx context.Context, userID, sessionID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if userID == "" || sessionID == "" {
		return iam.ErrSessionRevoked
	}
	usable, signedIn, err := userLive(ctx, s.pg, userID, iam.SessionRef{SessionID: sessionID})
	switch {
	case err != nil:
		return err
	case !usable || !signedIn:
		return iam.ErrSessionRevoked
	}
	return nil
}

// sessionAssurance is the session's auth_time, amr and acr, as an access
// token minted from it would carry them.
func (s *Engine) sessionAssurance(ctx context.Context, userID, sessionID string) (int64, []string, string, error) {
	fresh, err := s.SessionFreshness(ctx, userID, sessionID, s.nowTime())
	if err != nil {
		return 0, nil, "", err
	}
	mfa, mfaErr := s.mfaStatus(ctx, userID)
	authTime, amr, acr := fresh.AssuranceClaims(mfaErr != nil || mfa.Satisfied)
	return authTime, amr, acr, nil
}

// oauthMint is what one token response is minted for: a user's sign-in
// (userID, sessionID and its assurance), a workload's capability, or with no
// userID the client itself; jkt binds the access token to a DPoP key.
type oauthMint struct {
	client    config.OAuthClientConfig
	userID    string
	sessionID string
	scopes    []string
	resource  string
	nonce     string
	authTime  int64
	amr       []string
	acr       string
	jkt       string
	// invoker acts for the user (RFC 8693 act, delegation): the jwt-bearer
	// workload.
	invoker string
	// workload is a jwt-bearer token: it stands on deviceKeyID's capability,
	// which grantEnd ends; no sign-in stands behind it (no auth_time, amr or
	// acr) and it carries no permissions. decision is the host authorizer's.
	workload    bool
	deviceKeyID string
	grantEnd    time.Time
	decision    *authflow.OAuthGrantDecision
}

// mintOAuthTokens mints the access token for m's resource (or, with none,
// for userinfo) and, for a user with the openid scope, the ID token. The
// permissions are read live: the user's root grants, or the client's own,
// within the resource's ceiling.
func (s *Engine) mintOAuthTokens(ctx context.Context, m oauthMint) (authflow.OAuthTokens, error) {
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return authflow.OAuthTokens{}, iam.ErrSigningNotConfigured
	}
	now := s.nowTime()
	ttl := s.cfg.AuthorizationServer.AccessTokenTTL
	if m.workload {
		ttl = devicekey.MaxCapabilityLifetime + authflow.AssertionSkew // grantEnd, the capability's exp, bounds it
	}
	if m.decision != nil && m.decision.MaxLifetime > 0 && m.decision.MaxLifetime < ttl {
		ttl = m.decision.MaxLifetime.Truncate(time.Second)
	}
	if !m.grantEnd.IsZero() {
		if left := m.grantEnd.Sub(now).Truncate(time.Second); left < ttl {
			ttl = left
		}
		if ttl < time.Second {
			return authflow.OAuthTokens{}, errOAuthGrantRefused
		}
	}
	issuer := s.cfg.Token.Issuer
	audience := m.resource
	if audience == "" {
		audience = issuer
	}
	jti, err := newUUIDV7String()
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	resource, _ := config.FindResourceServer(s.cfg.AuthorizationServer, m.resource)
	at := map[string]any{
		"iss": issuer, "aud": audience, "client_id": m.client.ID,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": jti,
	}
	if len(m.scopes) > 0 {
		at["scope"] = strings.Join(m.scopes, " ")
	}
	if m.jkt != "" {
		at["cnf"] = map[string]any{jose.JWKThumbprintMember: m.jkt}
	}
	var details json.RawMessage
	if m.decision != nil {
		details = m.decision.AuthorizationDetails
		for name, value := range m.decision.Claims {
			at[name] = value
		}
	}
	if len(details) > 0 {
		at["authorization_details"] = details
	}
	if m.invoker != "" {
		at["act"] = map[string]any{"sub": m.invoker}
	}
	if m.workload {
		at["device_key_id"] = m.deviceKeyID
	}
	permissions, err := s.grantPermissions(ctx, m, resource.Permissions)
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	at["permissions"] = permissions
	if m.userID == "" {
		at["sub"] = m.client.ID
		access, err := jose.Sign(ctx, signer, jose.ResourceAccessTokenType, at)
		if err != nil {
			return authflow.OAuthTokens{}, err
		}
		return oauthAnswer(access, m, ttl, details), nil
	}
	u, err := s.getUserByID(ctx, m.userID)
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	if u == nil {
		return authflow.OAuthTokens{}, iam.ErrUserNotFound
	}
	roles := s.oauthRoles(ctx, m.userID)
	at["sub"], at["roles"] = m.userID, roles
	if !m.workload {
		maps.Copy(at, map[string]any{"auth_time": m.authTime, "acr": m.acr, "amr": m.amr})
	}
	if m.sessionID != "" {
		at["sid"] = m.sessionID
	}
	if (slices.Contains(m.scopes, "email") || resource.ContactClaims) && u.Email != nil {
		at["email"], at["email_verified"] = *u.Email, u.EmailVerified
	}
	if resource.ContactClaims {
		if u.Username != nil {
			at["preferred_username"], at["name"] = *u.Username, *u.Username
		}
		at["updated_at"] = u.ProfileUpdatedAt.Unix()
	}
	access, err := jose.Sign(ctx, signer, jose.ResourceAccessTokenType, at)
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	out := oauthAnswer(access, m, ttl, details)
	if slices.Contains(m.scopes, "openid") {
		id := map[string]any{
			"iss": issuer, "sub": m.userID, "aud": []string{m.client.ID}, "azp": m.client.ID,
			"iat": now.Unix(), "exp": now.Add(oauthIDTokenTTL).Unix(),
			"auth_time": m.authTime, "acr": m.acr, "amr": m.amr, "roles": roles,
		}
		if m.sessionID != "" {
			id["sid"] = m.sessionID
		}
		if m.nonce != "" {
			id["nonce"] = m.nonce
		}
		s.addProfileClaims(ctx, id, u, m.scopes)
		if out.IDToken, err = jose.Sign(ctx, signer, idTokenType, id); err != nil {
			return authflow.OAuthTokens{}, err
		}
	}
	return out, nil
}

func oauthAnswer(access string, m oauthMint, ttl time.Duration, details json.RawMessage) authflow.OAuthTokens {
	out := authflow.OAuthTokens{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(ttl / time.Second), Scope: strings.Join(m.scopes, " "), AuthorizationDetails: details}
	if m.jkt != "" {
		out.TokenType = "DPoP"
	}
	return out
}

// intersectGrants is what both grant sets allow, as grant patterns: each
// held grant narrowed to the ceiling, without one covered by another. Grant
// patterns are <persona>:*, <persona>:<resource>:* or a concrete permission
// (ident.ValidateGrantPattern), so two either nest or are disjoint.
func intersectGrants(held, ceiling []string) []string {
	var out []string
	for _, h := range held {
		for _, c := range ceiling {
			hp, cp := ident.Perm(h), ident.Perm(c)
			switch {
			case hp.Matches(cp): // h within c
				out = append(out, h)
			case cp.Matches(hp): // c within h
				out = append(out, c)
			}
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	kept := make([]string, 0, len(out))
	for i, p := range out {
		covered := false
		for j, q := range out {
			if i != j && ident.Perm(p).Matches(ident.Perm(q)) && p != q {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, p)
		}
	}
	return kept
}

// addProfileClaims sets the standard claims the granted scopes release.
func (s *Engine) addProfileClaims(_ context.Context, claims map[string]any, u *db.User, scopes []string) {
	if slices.Contains(scopes, "profile") && u.Username != nil {
		claims["preferred_username"] = *u.Username
	}
	if slices.Contains(scopes, "email") && u.Email != nil {
		claims["email"], claims["email_verified"] = *u.Email, u.EmailVerified
	}
}

// oauthRoles are the user's root-group role names ("admin"), an
// informational claim: resource servers authorize from permissions. Never
// nil.
func (s *Engine) oauthRoles(ctx context.Context, userID string) []string {
	if role := s.displayRootRole(ctx, s.q, userID); role != "" {
		return []string{strings.TrimPrefix(role, iam.RootPersona().String()+":")}
	}
	return []string{}
}

// verifyOwnToken checks a token's signature against this deployment's keys
// and, when typ is set, its header typ. Expiry is the caller's.
func (s *Engine) verifyOwnToken(token, typ string) (map[string]any, error) {
	if token == "" || len(token) > 32<<10 {
		return nil, jose.ErrSignature
	}
	gotTyp, claims, err := jose.Verify(token, func(_, kid string, _ map[string]any) (crypto.PublicKey, error) {
		key, ok := s.keys.PublicKeys()[kid]
		if !ok || key == nil {
			return nil, fmt.Errorf("unknown signing key %q", kid)
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	if typ != "" && !strings.EqualFold(gotTyp, typ) {
		return nil, fmt.Errorf("token typ %q, want %q", gotTyp, typ)
	}
	if jose.String(claims, "iss") != s.cfg.Token.Issuer {
		return nil, errors.New("token issued by another issuer")
	}
	return claims, nil
}

// oauthAudit records an authorization-server decision in the structured
// log: what happened, for whom, through which client. Never a secret.
func (s *Engine) oauthAudit(_ context.Context, event, userID string, fields map[string]string) {
	attrs := []any{slog.String("event", event), slog.String("user_id", userID)}
	for _, k := range slices.Sorted(maps.Keys(fields)) {
		attrs = append(attrs, slog.String(k, fields[k]))
	}
	slog.Default().Info("authkit: oauth", attrs...)
}

// pkceVerifies checks an RFC 7636 S256 verifier against its challenge.
func pkceVerifies(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 || strings.TrimLeft(verifier, pkceAlphabet) != "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return secret.Equal(base64.RawURLEncoding.EncodeToString(sum[:]), challenge)
}

// pkceAlphabet is RFC 7636's unreserved characters.
const pkceAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// oauthRedirect appends params to a registered redirect URI, keeping any
// query it already has.
func oauthRedirect(base string, params url.Values) (string, error) {
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

func optional(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}
