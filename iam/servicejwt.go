package iam

import (
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

const (
	// ServiceJWTTokenUse is the required `token_use` claim for service JWTs.
	ServiceJWTTokenUse = "service"
	// DefaultServiceJWTLifetime is the recommended lifetime for first-party
	// machine-to-machine service JWTs.
	DefaultServiceJWTLifetime = 15 * time.Minute
)

// ErrInvalidServiceJWT indicates a presented service JWT failed verification.
var ErrInvalidServiceJWT Error = errmodel.E(errmodel.CodeInvalidServiceJWT)

// ServiceJWT is a first-party machine-to-machine JWT to mint. It grants
// nothing AuthKit enforces; the receiver authorizes its permissions.
type ServiceJWT struct {
	Subject     string
	Audiences   []string
	Permissions []string
	// TTL defaults to, and is capped at, DefaultServiceJWTLifetime.
	TTL       time.Duration
	NotBefore time.Time
	IssuedAt  time.Time
	JTI       string
}

// ServiceJWTClaims is the claim shape of a service JWT. Permissions are
// requested capabilities; receivers intersect them with their own grants.
type ServiceJWTClaims struct {
	Issuer      string
	Subject     string
	Audiences   []string
	IssuedAt    time.Time
	NotBefore   time.Time
	ExpiresAt   time.Time
	JTI         string
	TokenUse    string
	Permissions []string
}
