package identity

import (
	"strings"

	"github.com/google/uuid"
)

// Stable identity from slug/username, applied at creation time.
//
// Org and user IDs are derived deterministically from the slug/username at
// the INSERT site (see core/service_orgs.go, service_owner_namespace.go,
// service_owner_namespace_state.go, service.go). After creation the ID is
// pinned and survives slug renames untouched — the *_slug_aliases tables
// continue to handle backwards lookup of old names. So the deterministic
// property holds at *birth*: a row's ID always reflects the slug it was
// originally created with.
//
// Why deterministic at all:
//   - Survives `docker compose down -v` in dev: same slug → same UUID,
//     so existing MinIO blob trees (keyed by owner UUID) re-attach to a
//     fresh DB without a blob migration.
//   - Operator scripts and federation flows can predict the canonical ID
//     for a known slug without a DB round-trip.
//   - Cross-environment parity (dev/staging/prod sharing public slugs all
//     converge on the same UUID, useful for content-addressed blob reuse).
//
// Same pattern as authkit/roles/ids.go (which derives role IDs from role
// slugs). Each kind gets its own namespace UUID so the keyspaces never
// collide — `org:foo` and `user:foo` produce different IDs.
//
// Acknowledged behavioral consequence: hard-deleting an org/user and
// recreating with the same slug yields the same UUID. Recreated owner
// silently dedups against any predecessor blobs in S3 until cas_blob_gc
// collects them. Acceptable for the open-source / dev workflow; a
// managed-SaaS deployment that needs slug recycling to be cryptographically
// distinct would layer on a "burn the namespace" step at delete time.

// NamespaceCozyOrgs is the UUID v5 namespace for org IDs. Fixed at first
// commit; never rotate (rotating breaks every existing reference).
var NamespaceCozyOrgs = uuid.MustParse("1d77e9f4-6b0c-4ee5-9e8b-2c5d0c5fa847")

// NamespaceCozyUsers is the UUID v5 namespace for user IDs. Distinct from
// NamespaceCozyOrgs so an org and user with identical slugs map to
// different UUIDs.
var NamespaceCozyUsers = uuid.MustParse("8f1e3a2b-4d6c-4f5a-9b8c-7e2d1c3f4a5b")

// OrgIDFromSlug returns the deterministic UUID for an org with this slug.
// Slug is canonicalized (trimmed, lowercased) before hashing — callers who
// pass already-validated slugs (which `validateOrgSlug` enforces lowercase)
// get a no-op canonicalization, but defending against accidental
// case-mismatches keeps the UUID stable.
func OrgIDFromSlug(slug string) uuid.UUID {
	s := strings.ToLower(strings.TrimSpace(slug))
	return uuid.NewSHA1(NamespaceCozyOrgs, []byte("org:"+s))
}

// UserIDFromUsername returns the deterministic UUID for a user with this
// username. Same canonicalization rule as OrgIDFromSlug.
func UserIDFromUsername(username string) uuid.UUID {
	s := strings.ToLower(strings.TrimSpace(username))
	return uuid.NewSHA1(NamespaceCozyUsers, []byte("user:"+s))
}
