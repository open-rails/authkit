package core

import (
	"context"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// Verifier is the minimal surface needed to validate JWT access tokens.
//
// It intentionally avoids exposing storage/transport details; implementations
// may be fully stateless (JWKS-only) or service-backed.
type Verifier interface {
	JWKS() jwtkit.JWKS
	Keyfunc() func(token *jwt.Token) (any, error)
	Options() Options

	// Optional enrichment hooks (best-effort).
	// Middleware can use these to fetch fresh roles/usernames when available.
	ListRoleSlugsByUser(ctx context.Context, userID string) []string
	GetProviderUsername(ctx context.Context, userID, provider string) (string, error)
}
