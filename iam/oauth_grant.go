package iam

import (
	"context"
	"encoding/json"
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

// ErrOAuthGrantRefused is returned (or wrapped) by an OAuthGrantAuthorizer to
// refuse a grant as a policy decision; any other error is an outage, and the
// request fails without changing the grant.
var ErrOAuthGrantRefused Error = errmodel.E(errmodel.CodeOAuthGrantRefused)

// OAuthGrantKind is the authorization-server step an OAuthGrantAuthorizer
// decides.
type OAuthGrantKind string

const (
	// OAuthGrantConsent is the user approving an authorization request; the
	// decision is what the authorization code (and its refresh tokens) carry.
	OAuthGrantConsent OAuthGrantKind = "consent"
	// OAuthGrantRefresh is a refresh token's redemption: every one is
	// re-decided, and a refusal ends the grant.
	OAuthGrantRefresh OAuthGrantKind = "refresh_token"
	// OAuthGrantTokenExchange is an RFC 8693 token exchange.
	OAuthGrantTokenExchange OAuthGrantKind = "token_exchange"
	// OAuthGrantClientCredentials is a confidential client acting for
	// itself.
	OAuthGrantClientCredentials OAuthGrantKind = "client_credentials"
	// OAuthGrantJWTBearer is an RFC 7523 JWT-bearer grant: a workload
	// proves its key (Assertion, JWKThumbprint) and presents a Capability
	// one of the user's device keys signed for that key: the operations
	// (AuthorizationDetails) it may do for the user on Resource.
	OAuthGrantJWTBearer OAuthGrantKind = "jwt_bearer"
)

// OAuthGrantRequest is one grant decision for the host (Deps.OAuthGrants).
type OAuthGrantRequest struct {
	Kind OAuthGrantKind
	// GrantID names a consented grant from consent through every refresh;
	// RevokeOAuthGrant ends it. Empty for token exchange, client credentials
	// and jwt-bearer, which have no refresh tokens.
	GrantID  string
	ClientID string
	// UserID is the user the grant is for; empty for client credentials.
	UserID string
	// SessionID or DeviceKeyID is the sign-in that consented (or the
	// exchanged token's): a refresh session or a device key. A grant ends
	// with it, unless offline. For jwt-bearer, DeviceKeyID is the live key
	// that signed the capability.
	SessionID   string
	DeviceKeyID string
	Resource    string
	Scopes      []string
	// AuthorizationDetails is the RFC 9396 authorization_details array: as
	// requested, on refresh as the grant carries it, for jwt-bearer as the
	// capability grants it. Nil when absent.
	AuthorizationDetails json.RawMessage
	// JWKThumbprint is the DPoP key (RFC 7638 thumbprint) the grant is
	// bound to, or the token request proves; empty for a bearer grant. For
	// jwt-bearer it is the key that signed Assertion.
	JWKThumbprint string
	// Offline is a grant whose refresh tokens outlive the sign-in (the
	// offline_access scope); changing the account's credentials ends it.
	Offline bool
	// Assertion and Capability are a jwt-bearer grant's, verified; nil
	// otherwise.
	Assertion  *OAuthAssertion
	Capability *OAuthCapability
}

// OAuthAssertion is a verified RFC 7523 assertion: signed by the key the
// request's JWKThumbprint names, which the token request also proved with
// DPoP. AuthKit checked its iss (the client), aud (the token endpoint),
// lifetime and jti; the rest is the workload's own say.
type OAuthAssertion struct {
	// Subject (sub) is the workload as it names itself.
	Subject string
	// ID (jti) redeems once per key.
	ID string
	// IssuedAt (iat) is zero when absent.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Claims are its claims AuthKit does not define, raw JSON by name; nil
	// when there are none.
	Claims map[string]json.RawMessage
}

// OAuthCapability is a verified capability: a JWT the request's UserID
// signed offline with its live device key DeviceKeyID, letting the workload
// key JWKThumbprint do AuthorizationDetails on Resource until ExpiresAt.
type OAuthCapability struct {
	// ID (jti) redeems once per device key: one token per capability.
	ID string
	// IssuedAt (iat) is zero when absent.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Claims are its claims AuthKit does not define (a run id, say), raw
	// JSON by name; nil when there are none.
	Claims map[string]json.RawMessage
}

// OAuthGrantDecision is the authority AuthKit mints for one grant. Its zero
// value grants the defaults: the user's live root-group grants (a client's
// own Permissions for client credentials) within the resource's ceiling;
// for jwt-bearer, no permissions and the capability's operations.
type OAuthGrantDecision struct {
	// Permissions, when non-nil, replace the default permissions. One in an
	// AuthKit persona's namespace must be held live by the user; the host's
	// own vocabulary is the host's decision. Either way the token carries
	// them only within the resource's ceiling. A jwt-bearer token carries
	// none: leave it nil.
	Permissions []string
	// AuthorizationDetails is what the grant carries (RFC 9396), in the
	// access token and the token response; nil keeps the request's. For
	// jwt-bearer it may only narrow: each entry must equal one of the
	// capability's.
	AuthorizationDetails json.RawMessage
	// MaxLifetime caps the grant from its start (consent, or the token
	// request): no refresh or access token outlives it. It only shortens the
	// client's lifetimes (a jwt-bearer token's, the capability's); 0 adds no
	// cap.
	MaxLifetime time.Duration
	// Claims are added to the access token. Each name must be
	// collision-resistant: an absolute URI ("https://tensorhub.com/grant").
	Claims map[string]any
	// Invoker names the workload acting for the user in a jwt-bearer token
	// (act.sub, verify.Claims.Invoker); empty is the workload key's
	// JWKThumbprint. Other grants leave it empty.
	Invoker string
}

// OAuthGrantAuthorizer decides every grant of the authorization server
// (Deps.OAuthGrants): at consent, at token exchange, client credentials and
// jwt-bearer, and at every refresh. It runs on the request path, so keep it fast; a
// consent it allows may still never be redeemed.
type OAuthGrantAuthorizer func(context.Context, OAuthGrantRequest) (OAuthGrantDecision, error)
