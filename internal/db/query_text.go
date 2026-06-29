package db

// QueryText exposes generated query SQL by query name for the plan/performance
// harness (internal/db/querytest). The values ARE the sqlc-generated constants,
// so the SQL the harness EXPLAINs can never drift from what the application runs
// — the whole point of the perf gate. Keys are the sqlc `-- name:` identifiers.
//
// Membership here is the set of queries the perf harness measures; the SQL text
// itself is always the live generated constant. Add an entry when a query joins
// the perf gate.
var QueryText = map[string]string{
	// Index-backed access patterns over growable tables (gated: no seq scan).
	"UserByEmail":                userByEmail,
	"UserByUsername":             userByUsername,
	"IdentityUsersByIDs":         identityUsersByIDs,
	"SessionByCurrentTokenHash":  sessionByCurrentTokenHash,
	"SessionByPreviousTokenHash": sessionByPreviousTokenHash,
	"SessionsListByUser":         sessionsListByUser,
	"SessionsEvictOldest":        sessionsEvictOldest,
	"ProviderLinkByIssuer":       providerLinkByIssuer,
	"UserProviderSlugs":          userProviderSlugs,
	"ProviderLinkBySlug":         providerLinkBySlug,   // gated since migration 003 added user_providers_slug_subject_idx
	"IdentityForwardUsername":    identityForwardUsername,
	"UsersPurgeCandidates":       usersPurgeCandidates,
	"SessionsRevokeFamily":       sessionsRevokeFamily, // gated since migration 002 added refresh_sessions_family_active

	// Catalogued finding — CONFIRMED to sequential-scan refresh_sessions at scale
	// (see querytest/README.md "Findings"). It is a periodic GC sweep, so a full
	// scan is acceptable; not gated.
	"SessionsDeleteRevokedOrExpired": sessionsDeleteRevokedOrExpired,
}
