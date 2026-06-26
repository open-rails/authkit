package authkit

import (
	"errors"
	"time"
)

const (
	// ServiceJWTTokenUse is the required `token_use` claim for service JWTs.
	ServiceJWTTokenUse = "service"
	// DefaultServiceJWTLifetime is the recommended lifetime for first-party
	// machine-to-machine service JWTs.
	DefaultServiceJWTLifetime = 15 * time.Minute
)

// ErrInvalidServiceJWT indicates a presented service JWT failed verification.
var ErrInvalidServiceJWT = errors.New("invalid_service_jwt")

// ServiceJWTClaims is the canonical AuthKit claim shape for caller-minted
// machine-to-machine JWTs. Permissions are requested capabilities; receiving
// services must still intersect them with server-side grants.
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
	Scope       []string
}
