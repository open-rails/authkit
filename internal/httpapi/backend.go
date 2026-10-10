package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/helpers/auth"
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
	flowsBackend
	oauthBackend
	scimBackend
	scimDirectoryBackend
	resourceBackend
}

// resourceBackend authenticates every credential the deployment accepts:
// its own, and with Config.Resource the access tokens minted for it.
type resourceBackend interface {
	Authenticate(r *http.Request) (auth.Verified, error)
}
