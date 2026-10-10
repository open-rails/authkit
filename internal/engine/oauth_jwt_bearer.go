package engine

// The RFC 7523 JWT-bearer grant (#437): a workload signs an assertion with
// its own key, proves the same key with DPoP, and presents a capability the
// user signed offline with a live device key: the operations the workload
// may do for the user on one resource. The host's grant authorizer may
// refuse or narrow them. AuthKit keeps nothing per workload but the spent
// jtis.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/secret"
)

const (
	keyOAuthAssertion  = "oauth:assertion:"  // +hash of the workload key and jti
	keyOAuthCapability = "oauth:capability:" // +hash of the device key and jti
)

// OAuthJWTBearer redeems a workload's assertion and the capability it
// carries for an access token to the capability's resource: for its user,
// bound to the workload key, carrying its operations (as the grant
// authorizer narrows them) until it expires. Nothing is spent until the
// token is minted, so a failure may be retried with the same capability.
func (s *Engine) OAuthJWTBearer(ctx context.Context, in authflow.OAuthJWTBearer) (authflow.OAuthTokens, error) {
	client, ok := config.FindOAuthClient(s.cfg.AuthorizationServer, in.ClientID)
	if !ok {
		return authflow.OAuthTokens{}, &authflow.OAuthError{Code: authflow.OAuthInvalidClient, Description: "unknown client", Status: 401}
	}
	now := s.nowTime()
	a, oerr := authflow.ParseJWTBearerAssertion(in.Assertion, client.ID, s.oauthTokenEndpoint(), now)
	switch {
	case oerr != nil:
		return authflow.OAuthTokens{}, oerr
	case in.JKT == "":
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidDPoPProof, "the jwt-bearer grant needs a DPoP proof of the assertion's key")
	case !secret.Equal(in.JKT, a.JKT):
		return authflow.OAuthTokens{}, &authflow.OAuthError{Code: authflow.OAuthInvalidDPoPProof, Description: "the DPoP proof must be signed by the assertion's key", Reason: authflow.ReasonKeyMismatch}
	case len(in.Scopes) > 0:
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidScope, "the jwt-bearer grant takes no scope: its capability's authorization_details are its authority")
	}
	c, err := s.verifyCapability(ctx, a.Capability, now)
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	switch {
	case !secret.Equal(c.JKT, a.JKT):
		return authflow.OAuthTokens{}, authflow.JWTBearerRefusal(authflow.ReasonKeyMismatch, "the capability is bound to another workload key")
	case in.Resource != "" && in.Resource != c.Audience:
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidTarget, "resource must be the capability's aud")
	}
	resource, ok := config.FindResourceServer(s.cfg.AuthorizationServer, c.Audience)
	if !ok || !slices.Contains(client.Resources, resource.ID) {
		return authflow.OAuthTokens{}, authflow.NewOAuthError(authflow.OAuthInvalidTarget, "the capability's aud is not a resource the client may request tokens for")
	}
	details, oerr := authflow.ParseAuthorizationDetails(string(c.AuthorizationDetails), client.AuthorizationDetailsTypes)
	if oerr != nil {
		return authflow.OAuthTokens{}, authflow.JWTBearerRefusal(authflow.ReasonCapabilityInvalid, "the capability's "+oerr.Description)
	}
	decision, err := s.decideOAuthGrant(ctx, iam.OAuthGrantRequest{
		Kind: iam.OAuthGrantJWTBearer, ClientID: client.ID, UserID: c.UserID, DeviceKeyID: c.DeviceKeyID,
		Resource: resource.ID, AuthorizationDetails: details, JWKThumbprint: a.JKT,
		Assertion:  &iam.OAuthAssertion{Subject: a.Subject, ID: a.ID, IssuedAt: a.IssuedAt, ExpiresAt: a.ExpiresAt, Claims: a.Claims},
		Capability: &iam.OAuthCapability{ID: c.ID, IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt, Claims: c.Claims},
	}, client.AuthorizationDetailsTypes)
	switch {
	case errors.Is(err, errOAuthGrantRefused):
		s.oauthAudit(ctx, "oauth_grant_refused", c.UserID, map[string]string{"client_id": client.ID, "grant_type": string(iam.OAuthGrantJWTBearer), "capability_jti": c.ID, "device_key_id": c.DeviceKeyID})
		return authflow.OAuthTokens{}, authflow.JWTBearerRefusal(authflow.ReasonRefused, "the grant was refused")
	case err != nil:
		return authflow.OAuthTokens{}, &authflow.OAuthError{Code: authflow.OAuthTemporarilyUnavailable, Description: "the grant cannot be decided now; retry later", Status: 503}
	}
	tokens, err := s.mintOAuthTokens(ctx, oauthMint{
		client: client, userID: c.UserID, deviceKeyID: c.DeviceKeyID, resource: resource.ID,
		jkt: a.JKT, decision: decision, invoker: decision.Invoker, workload: true, grantEnd: c.ExpiresAt,
	})
	if errors.Is(err, errOAuthGrantRefused) {
		return authflow.OAuthTokens{}, authflow.JWTBearerRefusal(authflow.ReasonCapabilityExpired, "the capability has expired")
	}
	if err != nil {
		return authflow.OAuthTokens{}, err
	}
	// The assertion first: a lost race spends only what the workload remakes.
	if err := s.spendAssertion(ctx, a.JKT, a.ID, a.ExpiresAt, now,
		authflow.JWTBearerRefusal(authflow.ReasonAssertionReplayed, "the assertion was already used")); err != nil {
		return authflow.OAuthTokens{}, err
	}
	if err := s.spendJTI(ctx, keyOAuthCapability, c.DeviceKeyID, c.ID, c.ExpiresAt, now,
		authflow.JWTBearerRefusal(authflow.ReasonCapabilityReplayed, "the capability was already redeemed")); err != nil {
		return authflow.OAuthTokens{}, err
	}
	s.oauthAudit(ctx, "oauth_jwt_bearer", c.UserID, map[string]string{
		"client_id": client.ID, "resource": resource.ID, "invoker": decision.Invoker, "jkt": a.JKT,
		"device_key_id": c.DeviceKeyID, "capability_jti": c.ID,
	})
	return tokens, nil
}

// verifyCapability verifies raw against the live device key it names, whose
// user must be its sub and usable.
func (s *Engine) verifyCapability(ctx context.Context, raw string, now time.Time) (authflow.Capability, error) {
	kid, oerr := authflow.CapabilityKeyID(raw)
	if oerr != nil {
		return authflow.Capability{}, oerr
	}
	if err := s.requirePG(); err != nil {
		return authflow.Capability{}, err
	}
	revoked := authflow.JWTBearerRefusal(authflow.ReasonDeviceKeyRevoked, "the capability's device key is unknown or revoked")
	key, err := s.q.DeviceKeyActive(ctx, kid)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return authflow.Capability{}, revoked
	case err != nil:
		return authflow.Capability{}, err
	}
	c, oerr := authflow.VerifyCapability(raw, kid, key.PublicKey, now)
	switch {
	case oerr != nil:
		return authflow.Capability{}, oerr
	case !strings.EqualFold(c.UserID, key.UserID):
		return authflow.Capability{}, authflow.JWTBearerRefusal(authflow.ReasonCapabilityInvalid, "the capability's sub is not its device key's user")
	}
	usable, live, err := userLive(ctx, s.pg, c.UserID, iam.SessionRef{DeviceKeyID: kid})
	switch {
	case err != nil:
		return authflow.Capability{}, err
	case !live:
		return authflow.Capability{}, revoked
	case !usable:
		return authflow.Capability{}, authflow.JWTBearerRefusal(authflow.ReasonUserUnavailable, "the capability's user is unavailable")
	}
	return c, nil
}

// spendJTI claims signer's jti in Postgres until exp can no longer be
// accepted, for a grant record whose spent state survives restarts (a
// capability); a second claim answers spent.
func (s *Engine) spendJTI(ctx context.Context, prefix, signer, jti string, exp, now time.Time, spent *authflow.OAuthError) error {
	n, err := s.ephemIncr(ctx, prefix+jtiKey(signer, jti), jtiTTL(exp, now))
	switch {
	case err != nil:
		return err
	case n != 1:
		return spent
	}
	return nil
}

// spendAssertion claims signer's assertion jti (RFC 7523 §3) in the replay
// store DPoP proofs are spent in, until exp can no longer be accepted; a
// second claim answers spent.
func (s *Engine) spendAssertion(ctx context.Context, signer, jti string, exp, now time.Time, spent *authflow.OAuthError) error {
	claimed, err := s.replays.Claim(ctx, keyOAuthAssertion+jtiKey(signer, jti), jtiTTL(exp, now))
	switch {
	case err != nil:
		return &authflow.OAuthError{Code: authflow.OAuthTemporarilyUnavailable, Description: "the assertion cannot be checked now; retry later", Status: 503}
	case !claimed:
		return spent
	}
	return nil
}

func jtiKey(signer, jti string) string {
	sum := sha256.Sum256([]byte(signer + "." + jti))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// jtiTTL is how long a jti expiring at exp can still be accepted.
func jtiTTL(exp, now time.Time) time.Duration {
	return exp.Add(authflow.AssertionSkew).Sub(now).Truncate(time.Second) + time.Second
}

// oauthTokenEndpoint is the token endpoint's URL, an assertion's aud.
func (s *Engine) oauthTokenEndpoint() string {
	if s.cfg.HTTP == nil {
		return ""
	}
	return strings.TrimRight(s.cfg.HTTP.PublicURL, "/") + iam.OAuthTokenPath
}
