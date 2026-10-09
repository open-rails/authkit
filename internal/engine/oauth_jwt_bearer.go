package engine

// The RFC 7523 JWT-bearer grant (#437): a workload signs an assertion with
// its own key and proves the same key with DPoP; the host's grant authorizer
// recognizes the key and names the user the token acts for. AuthKit keeps
// nothing per workload but the assertion's spent jti.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/secret"
)

const keyOAuthAssertion = "oauth:assertion:" // +hash of the key thumbprint and jti

// OAuthJWTBearer redeems a workload's assertion once for an access token to
// one of the client's resources, bound to the assertion's key, acting for
// the user the grant authorizer names. It issues no refresh token: the
// workload asserts again.
func (s *Engine) OAuthJWTBearer(ctx context.Context, in authflow.OAuthJWTBearer) (authflow.OAuthTokens, error) {
	client, resource, err := s.oauthClientResource(in.ClientID, in.Resource)
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	now := s.nowTime()
	jkt, assertion, oerr := authflow.ParseJWTBearerAssertion(in.Assertion, client.ID, s.oauthTokenEndpoint(), now)
	switch {
	case oerr != nil:
		return authflow.OAuthTokens{}, oerr
	case in.JKT == "":
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidDPoPProof, "the jwt-bearer grant needs a DPoP proof of the assertion's key")
	case !secret.Equal(in.JKT, jkt):
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidDPoPProof, "the DPoP proof must be signed by the assertion's key")
	}
	scopes, oerr := grantScopes(in.Scopes, resource)
	if oerr != nil {
		return authflow.OAuthTokens{}, oerr
	}
	if err := s.spendAssertion(ctx, jkt, assertion, now); err != nil {
		return authflow.OAuthTokens{}, err
	}
	decision, err := s.decideOAuthGrant(ctx, iam.OAuthGrantRequest{
		Kind: iam.OAuthGrantJWTBearer, ClientID: client.ID, Resource: resource.ID, Scopes: scopes,
		JWKThumbprint: jkt, Assertion: &assertion,
	}, client.AuthorizationDetailsTypes)
	switch {
	case errors.Is(err, errOAuthGrantRefused):
		s.oauthAudit(ctx, "oauth_grant_refused", "", map[string]string{"client_id": client.ID, "jkt": jkt, "grant_type": string(iam.OAuthGrantJWTBearer)})
		return authflow.OAuthTokens{}, oauthGrantFailure(err, authflow.OAuthInvalidGrant)
	case err != nil:
		return authflow.OAuthTokens{}, oauthGrantFailure(err, authflow.OAuthInvalidGrant)
	case decision == nil:
		return authflow.OAuthTokens{}, errors.New("authkit: oauth: the jwt-bearer grant needs a grant authorizer")
	}
	if err := s.requirePG(); err != nil {
		return authflow.OAuthTokens{}, err
	}
	usable, _, err := userLive(ctx, s.pg, decision.UserID, iam.SessionRef{})
	switch {
	case err != nil:
		return authflow.OAuthTokens{}, err
	case !usable:
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidGrant, "the user the grant acts for is unavailable")
	}
	tokens, err := s.mintOAuthTokens(ctx, oauthMint{
		client: client, userID: decision.UserID, scopes: scopes, resource: resource.ID,
		jkt: jkt, decision: decision, invoker: decision.Invoker, workload: true,
	})
	if errors.Is(err, errOAuthGrantRefused) {
		return authflow.OAuthTokens{}, oauthGrantFailure(err, authflow.OAuthInvalidGrant)
	}
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	s.oauthAudit(ctx, "oauth_jwt_bearer", decision.UserID, map[string]string{
		"client_id": client.ID, "resource": resource.ID, "invoker": decision.Invoker, "jkt": jkt,
	})
	return tokens, nil
}

// spendAssertion claims a's jti for its key until it can no longer be
// accepted: presenting it again is invalid_grant.
func (s *Engine) spendAssertion(ctx context.Context, jkt string, a iam.OAuthAssertion, now time.Time) error {
	sum := sha256.Sum256([]byte(jkt + "." + a.ID))
	ttl := a.ExpiresAt.Add(authflow.AssertionSkew).Sub(now).Truncate(time.Second) + time.Second
	n, err := s.ephemIncr(ctx, keyOAuthAssertion+base64.RawURLEncoding.EncodeToString(sum[:]), ttl)
	switch {
	case err != nil:
		return err
	case n != 1:
		return authflow.NewOAuthError(authflow.OAuthInvalidGrant, "the assertion was already used")
	}
	return nil
}

// oauthTokenEndpoint is the token endpoint's URL, an assertion's aud.
func (s *Engine) oauthTokenEndpoint() string {
	if s.cfg.HTTP == nil {
		return ""
	}
	return strings.TrimRight(s.cfg.HTTP.PublicURL, "/") + iam.OAuthTokenPath
}
