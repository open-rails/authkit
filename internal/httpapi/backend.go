package httpapi

import "github.com/open-rails/authkit/internal/ops"

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
}
