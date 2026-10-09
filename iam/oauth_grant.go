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
)

// OAuthGrantRequest is one grant decision for the host (Deps.OAuthGrants).
type OAuthGrantRequest struct {
	Kind OAuthGrantKind
	// GrantID names a consented grant from consent through every refresh;
	// RevokeOAuthGrant ends it. Empty for token exchange and client
	// credentials, which have no refresh tokens.
	GrantID  string
	ClientID string
	// UserID is the user the grant is for; empty for client credentials.
	UserID string
	// SessionID is the sign-in that consented (or the exchanged token's).
	// An offline grant outlives it.
	SessionID string
	Resource  string
	Scopes    []string
	// AuthorizationDetails is the RFC 9396 authorization_details array: as
	// requested, or on refresh as the grant carries it. Nil when absent.
	AuthorizationDetails json.RawMessage
	// JWKThumbprint is the DPoP key (RFC 7638 thumbprint) the grant is
	// bound to, or the token request proves; empty for a bearer grant.
	JWKThumbprint string
	// Offline is a grant whose refresh tokens outlive the sign-in (the
	// offline_access scope); changing the account's credentials ends it.
	Offline bool
}

// OAuthGrantDecision is the authority AuthKit mints for one grant. Its zero
// value grants the defaults: the user's live root-group grants (a client's
// own Permissions for client credentials) within the resource's ceiling.
type OAuthGrantDecision struct {
	// Permissions, when non-nil, replace the default permissions. One in an
	// AuthKit persona's namespace must be held live by the user; the host's
	// own vocabulary is the host's decision. Either way the token carries
	// them only within the resource's ceiling.
	Permissions []string
	// AuthorizationDetails is what the grant carries (RFC 9396), in the
	// access token and the token response; nil keeps the request's.
	AuthorizationDetails json.RawMessage
	// MaxLifetime caps the grant from its start (consent, or the token
	// request): no refresh or access token outlives it. It only shortens the
	// client's lifetimes; 0 adds no cap.
	MaxLifetime time.Duration
	// Claims are added to the access token. Each name must be
	// collision-resistant: an absolute URI ("https://tensorhub.com/grant").
	Claims map[string]any
}

// OAuthGrantAuthorizer decides every grant of the authorization server
// (Deps.OAuthGrants): at consent, at token exchange and client credentials,
// and at every refresh. It runs on the request path, so keep it fast; a
// consent it allows may still never be redeemed.
type OAuthGrantAuthorizer func(context.Context, OAuthGrantRequest) (OAuthGrantDecision, error)
