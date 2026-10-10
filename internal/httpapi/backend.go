package httpapi

import (
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/internal/ratelimit"
)

// Backend is the engine capability the HTTP layer drives: the operations the
// Client exposes (ops.Operations) plus the flows only the HTTP layer runs.
// The engine implements it; hosts never see it. Each domain's flow methods
// live in its own backend_<domain>.go.
type Backend interface {
	ops.Operations
	usersBackend
	sessionsBackend
	groupsBackend
	invitesBackend
	appsBackend
	flowsBackend
	oauthBackend
	scimBackend
	// RateLimiter is the limiter every replica shares, in PostgreSQL.
	RateLimiter(limits map[string]ratelimit.Limit) (ratelimit.Limiter, error)
}
