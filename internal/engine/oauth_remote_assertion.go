package engine

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/jose"
)

// OAuthRemoteAssertion is the RFC 7523 §2.1 JWT-bearer grant for a trusted
// issuer's backend, with no authorization server of its own: it signs a
// short assertion with its registered remote application's key (iss its
// issuer, sub its user, aud the token endpoint, a jti spent once), and its
// frontend redeems it for an access token to Config.Resource.ID acting for
// that user in the application's group. The token holds no permissions; its
// client_id is the application's issuer, the namespace of its sub. A DPoP
// proof binds it, as the frontend chooses.
func (s *Engine) OAuthRemoteAssertion(ctx context.Context, in authflow.OAuthJWTBearer) (authflow.OAuthTokens, error) {
	if s.resource == nil {
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthUnsupportedGrantType, "this deployment is no resource server")
	}
	invalid := func(description string) *authflow.OAuthError {
		return authflow.NewOAuthError(authflow.OAuthInvalidGrant, description)
	}
	typ, unverified, ok := jose.Unverified(in.Assertion)
	if !ok || len(in.Assertion) > 16<<10 || (typ != "" && !strings.EqualFold(typ, "JWT")) {
		return authflow.OAuthTokens{}, invalid("the assertion is not a JWT")
	}
	app, err := s.resource.trusted(ctx, jose.String(unverified, "iss"))
	if err != nil {
		return authflow.OAuthTokens{}, invalid("the assertion's issuer is not a trusted remote application")
	}
	claims, err := s.resource.assertions.VerifyClaims(ctx, in.Assertion)
	if err != nil {
		return authflow.OAuthTokens{}, invalid("the assertion is invalid, expired or not for this token endpoint")
	}
	now := s.nowTime()
	sub, jti := jose.String(claims, "sub"), jose.String(claims, "jti")
	exp, _ := jose.Time(claims, "exp")
	switch {
	case sub == "" || len(sub) > 255:
		return authflow.OAuthTokens{}, invalid("the assertion names no subject")
	case len(jti) < 16 || len(jti) > 128:
		return authflow.OAuthTokens{}, invalid("the assertion's jti must be 16-128 characters")
	case exp.After(now.Add(authflow.MaxAssertionLifetime + authflow.AssertionSkew)):
		return authflow.OAuthTokens{}, invalid("the assertion expires too far ahead")
	case in.Resource != "" && in.Resource != s.cfg.Resource.ID:
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidTarget, "resource must be this deployment's")
	}
	for _, scope := range in.Scopes {
		if _, ok := s.cfg.Resource.Scopes[scope]; !ok {
			return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidScope, "unknown scope "+strconv.Quote(scope))
		}
	}
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return authflow.OAuthTokens{}, iam.ErrSigningNotConfigured
	}
	ttl := s.cfg.AuthorizationServer.AccessTokenTTL
	if ttl <= 0 {
		ttl = config.DefaultOAuthAccessTokenTTL
	}
	id, err := newUUIDV7String()
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	at := map[string]any{
		"iss": s.cfg.Token.Issuer, "aud": s.cfg.Resource.ID, "sub": sub, "client_id": app.Issuer,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(ttl).Unix(), "jti": id,
	}
	scopes := slices.Clone(in.Scopes)
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	if len(scopes) > 0 {
		at["scope"] = strings.Join(scopes, " ")
	}
	if in.JKT != "" {
		at["cnf"] = map[string]any{jose.JWKThumbprintMember: in.JKT}
	}
	// The application vouches for its user's contact (OIDC Core §5.1); an
	// email only when it says it is verified.
	if verified, _ := claims["email_verified"].(bool); verified && jose.String(claims, "email") != "" {
		at["email"], at["email_verified"] = jose.String(claims, "email"), true
	}
	for _, name := range []string{"name", "preferred_username"} {
		if v := jose.String(claims, name); v != "" && len(v) <= 255 {
			at[name] = v
		}
	}
	if updated, ok := jose.Time(claims, "updated_at"); ok {
		at["updated_at"] = updated.Unix()
	}
	if err := s.spendAssertion(ctx, app.ID, jti, exp, now, invalid("the assertion was already used")); err != nil {
		return authflow.OAuthTokens{}, err
	}
	access, err := jose.Sign(ctx, signer, jose.ResourceAccessTokenType, at)
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	s.oauthAudit(ctx, "oauth_remote_assertion", "", map[string]string{"issuer": app.Issuer, "subject": sub, "resource": s.cfg.Resource.ID, "jkt": in.JKT})
	tokenType := "Bearer"
	if in.JKT != "" {
		tokenType = "DPoP"
	}
	return authflow.OAuthTokens{AccessToken: access, TokenType: tokenType, ExpiresIn: int64(ttl / time.Second), Scope: strings.Join(scopes, " ")}, nil
}
