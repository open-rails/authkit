package iam

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

// ErrDelegationRefused is returned (or wrapped) by a DelegationAuthorizer to
// refuse a mint as a policy decision; any other error is an authorizer outage.
var ErrDelegationRefused Error = errmodel.E(errmodel.CodeDelegationRefused)

// DelegationRequest is what POST /delegated/token asks the host to authorize
// (ak#277). Audiences and TTL are already clamped; the certificate or DPoP
// sender proof is validated; RequestedGrant is the client's opaque, host-schema object that
// AuthKit never copies into the token.
type DelegationRequest struct {
	UserID                        string
	Audiences                     []string
	TTL                           time.Duration
	ConfirmationCertificateSHA256 [32]byte
	// ConfirmationJWKThumbprintSHA256 is set only after validating a DPoP proof.
	// DelegateCertificate is nil on this browser-capable path.
	ConfirmationJWKThumbprintSHA256 *[32]byte
	DelegateCertificate             *x509.Certificate
	RequestedGrant                  json.RawMessage
}

// DelegationGrant is the complete authority AuthKit signs for one request.
type DelegationGrant struct {
	Permissions []string
	Attributes  map[string]any
	Documents   map[string]string
}

// DelegationAuthorizer is the single host seam of the delegated mint route.
type DelegationAuthorizer func(context.Context, DelegationRequest) (DelegationGrant, error)

// DelegatedAccess is a delegated access token to mint: signed by this
// deployment, it carries delegated_sub and never sub.
type DelegatedAccess struct {
	// Subject becomes delegated_sub. A user actor mints only for itself (empty
	// means the actor); an operator must name the subject.
	Subject string
	// Audiences becomes aud: the resource APIs the token is for.
	Audiences []string
	// Permissions becomes the permissions claim. A permission in an AuthKit
	// persona's namespace must be held live by the subject on the root group;
	// the host's own vocabulary is the host's decision.
	Permissions []string
	// Documents are document references (type → sha256 digest) stamped next
	// to the documents this deployment publishes.
	Documents map[string]string
	// Attributes carries app-specific JSON. The documents key is reserved;
	// roles is set by Roles.
	Attributes map[string]any
	// Roles become attributes.roles.
	Roles []string
	// TTL is clamped to the Config.Delegated bounds (default 15m, at most 1h).
	TTL time.Duration
	// JTI becomes jti; empty mints a fresh one.
	JTI       string
	NotBefore time.Time
	// ConfirmationCertificateSHA256 binds the token to an X.509 certificate
	// (RFC 8705 cnf.x5t#S256), ConfirmationJWKThumbprintSHA256 to a DPoP key
	// (RFC 9449 cnf.jkt). At most one; neither mints a bearer token.
	ConfirmationCertificateSHA256   *[32]byte
	ConfirmationJWKThumbprintSHA256 *[32]byte
}
