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

// ServiceJWTClaims is the claim shape of a service JWT (iss, sub, aud, iat,
// nbf, exp, jti, token_use, permissions). Permissions are requested
// capabilities; receivers intersect them with their own grants.
type ServiceJWTClaims struct {
	Issuer      string    `json:"issuer"`
	Subject     string    `json:"subject"`
	Audiences   []string  `json:"audiences"`
	IssuedAt    time.Time `json:"issued_at"`
	NotBefore   time.Time `json:"not_before"`
	ExpiresAt   time.Time `json:"expires_at"`
	JTI         string    `json:"jti"`
	TokenUse    string    `json:"token_use"`
	Permissions []string  `json:"permissions"`
}
