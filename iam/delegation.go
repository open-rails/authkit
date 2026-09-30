package iam

import (
	"context"
	"encoding/json"
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

// ErrDelegationRefused is returned (or wrapped) by a DelegationAuthorizer to
// refuse a mint as a policy decision; any other error is an authorizer outage.
var ErrDelegationRefused Error = errmodel.E(errmodel.CodeDelegationRefused)

// DelegationRequest is what POST /delegated/token asks the host to authorize
// (ak#277). Audiences and TTL are already clamped; the sender proof is
// validated; RequestedGrant is the client's opaque, host-schema object that
// AuthKit never copies into the token. The token is bound to exactly one of
// the delegate's certificate and its DPoP key.
type DelegationRequest struct {
	UserID    string
	Audiences []string
	TTL       time.Duration
	// DelegateCertificate is the delegate's X.509 leaf (DER) and
	// CertificateThumbprint its x5t#S256; both empty on the DPoP path.
	DelegateCertificate   []byte
	CertificateThumbprint string
	// JWKThumbprint is the DPoP key's jkt; empty on the certificate path.
	JWKThumbprint  string
	RequestedGrant json.RawMessage
}

// DelegationGrant is the complete authority AuthKit signs for one request.
type DelegationGrant struct {
	Permissions []string
	Attributes  map[string]any
}

// DelegationAuthorizer is the single host seam of the delegated mint route.
type DelegationAuthorizer func(context.Context, DelegationRequest) (DelegationGrant, error)

// DelegatedAccess is a delegated access token to mint: signed by this
// deployment, it carries delegated_sub and never sub.
type DelegatedAccess struct {
	// Subject becomes delegated_sub. A user actor mints only for itself (empty
	// means the actor); the system must name the subject.
	Subject string
	// Audiences becomes aud: the resource APIs the token is for.
	Audiences []string
	// Permissions becomes the permissions claim. A permission in an AuthKit
	// persona's namespace must be held live by the subject on the root group;
	// the host's own vocabulary is the host's decision.
	Permissions []string
	// Attributes carries app-specific JSON; AuthKit assigns no key a meaning.
	Attributes map[string]any
	// TTL is clamped to the Config.Delegated bounds (default 15m, at most 1h).
	TTL time.Duration
	// JTI becomes jti; empty mints a fresh one.
	JTI       string
	NotBefore time.Time
	// CertificateThumbprint binds the token to an X.509 certificate (RFC 8705
	// cnf.x5t#S256), JWKThumbprint to a DPoP key (RFC 9449 cnf.jkt), each the
	// unpadded base64url SHA-256. At most one; neither mints a bearer token.
	CertificateThumbprint string
	JWKThumbprint         string
}
