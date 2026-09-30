package authflow

import (
	"time"
)

// ExternalIdentity is a provider-verified identity.
type ExternalIdentity struct {
	Provider          string // provider slug (the configured name)
	Issuer            string
	Subject           string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	DisplayName       string
}

// ExternalLoginInput is an external-identity login or link attempt.
type ExternalLoginInput struct {
	Identity ExternalIdentity
	// Link authorizes a provider mutation only; it never creates a session.
	Link               *ExternalLinkAuthorization
	AccountInviteToken string
	// ReturnTo is where the browser flow began; the sign-in's continuations
	// carry it to their AuthResult.
	ReturnTo  string
	Event     string // session-created audit event, e.g. "oidc_login"
	UserAgent string
	IP        string
}

// ExternalLinkAuthorization records the fresh session that initiated linking.
// It is carried only in server-side browser state, never accepted from a callback.
type ExternalLinkAuthorization struct {
	UserID          string
	SessionID       string
	AuthenticatedAt time.Time
}
