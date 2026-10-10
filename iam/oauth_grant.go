package iam

import (
	"context"
	"encoding/json"
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

// ErrOAuthGrantRefused is returned (or wrapped) by an OAuthGrantAuthorizer to
// refuse a grant as a policy decision; any other error is an outage, and the
// request fails without spending the capability.
var ErrOAuthGrantRefused Error = errmodel.E(errmodel.CodeOAuthGrantRefused)

// OAuthGrantKind is the authorization-server grant an OAuthGrantAuthorizer
// decides.
type OAuthGrantKind string

// OAuthGrantJWTBearer is an RFC 7523 JWT-bearer grant: a workload proves its
// key (Assertion, JWKThumbprint) and presents a Capability one of the user's
// device keys signed for that key: the operations (AuthorizationDetails) it
// may do for the user on Resource.
const OAuthGrantJWTBearer OAuthGrantKind = "jwt_bearer"

// OAuthGrantRequest is one grant decision for the host (Deps.OAuthGrants).
type OAuthGrantRequest struct {
	Kind     OAuthGrantKind
	ClientID string
	// UserID is the user the capability is for; DeviceKeyID the live device
	// key that signed it.
	UserID      string
	DeviceKeyID string
	Resource    string
	// AuthorizationDetails is the capability's RFC 9396
	// authorization_details array.
	AuthorizationDetails json.RawMessage
	// JWKThumbprint is the workload key (RFC 7638 thumbprint) that signed
	// Assertion and proved itself with DPoP.
	JWKThumbprint string
	// Assertion and Capability are the grant's, verified.
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

// OAuthGrantDecision is what AuthKit mints for one grant. Its zero value
// grants the capability's operations for its lifetime.
type OAuthGrantDecision struct {
	// AuthorizationDetails is what the token carries (RFC 9396), in the
	// access token and the token response; nil keeps the capability's. It
	// may only narrow: each entry must equal one of the capability's.
	AuthorizationDetails json.RawMessage
	// MaxLifetime caps the token from the token request; it only shortens
	// the capability's lifetime. 0 adds no cap.
	MaxLifetime time.Duration
	// Claims are added to the access token. Each name must be
	// collision-resistant: an absolute URI ("https://hub.example.com/run").
	Claims map[string]any
	// Invoker names the workload acting for the user (act.sub,
	// verify.Claims.Invoker); empty is the workload key's JWKThumbprint.
	Invoker string
}

// OAuthGrantAuthorizer decides each jwt-bearer grant of the authorization
// server (Deps.OAuthGrants). It runs on the request path, so keep it fast.
type OAuthGrantAuthorizer func(context.Context, OAuthGrantRequest) (OAuthGrantDecision, error)
