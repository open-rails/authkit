package authkit

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"time"
)

// ErrDelegationRefused is returned (or wrapped) by a DelegationAuthorizer to
// refuse a mint as a policy decision; any other error is an authorizer outage.
var ErrDelegationRefused = E(CodeDelegationRefused)

// DelegationRequest is what POST /delegated/token asks the host to authorize
// (ak#277). Audiences and TTL are already clamped; the certificate is parsed
// and validated; RequestedGrant is the client's opaque, host-schema object that
// AuthKit never copies into the token.
type DelegationRequest struct {
	UserID                        string
	Audiences                     []string
	TTL                           time.Duration
	ConfirmationCertificateSHA256 [32]byte
	DelegateCertificate           *x509.Certificate
	RequestedGrant                json.RawMessage
}

// DelegationGrant is the complete authority AuthKit signs for one request.
type DelegationGrant struct {
	Permissions []string
	Attributes  map[string]any
	Documents   map[string]string
}

// DelegationAuthorizer is the single host seam of the delegated mint route.
type DelegationAuthorizer func(context.Context, DelegationRequest) (DelegationGrant, error)
