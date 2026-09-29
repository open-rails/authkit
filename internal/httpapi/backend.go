package httpapi

// Backend is the engine capability the HTTP layer drives. The engine
// implements it; hosts never see it. Each domain's methods live in its own
// backend_<domain>.go.
type Backend interface {
	usersBackend
	sessionsBackend
	groupsBackend
	apiKeysBackend
	invitesBackend
	appsBackend
	flowsBackend
}
