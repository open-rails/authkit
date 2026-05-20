package core

import (
	"os"
	"strings"
	"testing"
)

// Issue #58 contract checks. These guard the SQL shape that the
// implementing agent committed against drift — they don't run against
// a real DB, just grep the source for the canonical statements.
//
// If you intentionally change one of these patterns, update the test
// AND make sure the corresponding writer/reader stays consistent.

func TestRenameOrgSlugWritesAuditRowAndChecksCooldown(t *testing.T) {
	src := readSource(t, "service_orgs.go")
	required := []string{
		// Cooldown query: top-1 by renamed_at DESC for this org.
		"FROM   profiles.org_renames",
		"ORDER  BY renamed_at DESC",
		// Audit row insert.
		"INSERT INTO profiles.org_renames (org_id, from_slug, to_slug, renamed_by)",
		// Cooldown error returned when within window.
		"return ErrRenameRateLimited",
		// Admin override service method.
		"RenameOrgSlugForce",
	}
	for _, marker := range required {
		if !strings.Contains(src, marker) {
			t.Fatalf("expected service_orgs.go to contain %q (issue #58)", marker)
		}
	}
	// Old alias-table writer must be gone.
	if strings.Contains(src, "INSERT INTO profiles.org_slug_aliases") {
		t.Fatalf("RenameOrgSlug should no longer write to org_slug_aliases (issue #58 dropped that table)")
	}
}

func TestUpdateUsernameWritesAuditRowAndChecksCooldown(t *testing.T) {
	src := readSource(t, "service.go")
	required := []string{
		// Cooldown query for user.
		"FROM   profiles.user_renames",
		// Audit row insert (user side).
		"INSERT INTO profiles.user_renames (user_id, from_slug, to_slug, renamed_by)",
		// Personal-org rename rides on the user-rename intent and
		// emits its own org_renames row in the same tx.
		"INSERT INTO profiles.org_renames (org_id, from_slug, to_slug, renamed_by)",
		// Admin override variant.
		"UpdateUsernameForce",
		// Cooldown error path.
		"return ErrRenameRateLimited",
	}
	for _, marker := range required {
		if !strings.Contains(src, marker) {
			t.Fatalf("expected service.go to contain %q (issue #58)", marker)
		}
	}
	if strings.Contains(src, "INSERT INTO profiles.user_slug_aliases") {
		t.Fatalf("updateUsername should no longer write to user_slug_aliases (issue #58 dropped that table)")
	}
}

func TestResolveOrgBySlugFallsThroughOrgRenames(t *testing.T) {
	src := readSource(t, "service_orgs.go")
	if !strings.Contains(src, "FROM profiles.org_renames r") {
		t.Fatalf("ResolveOrgBySlug must fall through profiles.org_renames on alias miss (issue #58)")
	}
	if !strings.Contains(src, "JOIN profiles.orgs o ON o.id=r.org_id AND o.deleted_at IS NULL") {
		t.Fatalf("ResolveOrgBySlug must resolve historical slugs through org_id to the live current org row")
	}
	if !strings.Contains(src, "SELECT o.id::text, o.slug") {
		t.Fatalf("ResolveOrgBySlug must return the current org slug from profiles.orgs, not the historical to_slug")
	}
	if strings.Contains(src, "FROM profiles.org_slug_aliases a") {
		t.Fatalf("ResolveOrgBySlug must not reference profiles.org_slug_aliases (table was dropped in issue #58)")
	}
}

func TestResolveUserBySlugFallsThroughUserRenamesToCurrentUsername(t *testing.T) {
	src := readSource(t, "service_owner_namespace.go")
	if !strings.Contains(src, "FROM profiles.user_renames r") {
		t.Fatalf("ResolveUserBySlug must fall through profiles.user_renames on username miss")
	}
	if !strings.Contains(src, "JOIN profiles.users u ON u.id=r.user_id AND u.deleted_at IS NULL") {
		t.Fatalf("ResolveUserBySlug must resolve historical usernames through user_id to the live current user row")
	}
	if !strings.Contains(src, "SELECT u.id::text, u.username::text") {
		t.Fatalf("ResolveUserBySlug must return the current username from profiles.users, not the historical to_slug")
	}
}

func TestRenameHistoryMigrationHasEfficientLookupIndexesAndNoHistoryUniqueness(t *testing.T) {
	src := readSource(t, "../migrations/postgres/001_auth_schema.up.sql")
	renameSrc := sourceBetween(t, src, "CREATE TABLE IF NOT EXISTS profiles.org_renames", "CREATE TABLE IF NOT EXISTS profiles.user_renames")
	renameSrc += sourceBetween(t, src, "CREATE TABLE IF NOT EXISTS profiles.user_renames", "")
	required := []string{
		"ON profiles.org_renames (from_slug, renamed_at DESC)",
		"ON profiles.user_renames (from_slug, renamed_at DESC)",
		"ON profiles.org_renames (org_id, renamed_at DESC)",
		"ON profiles.user_renames (user_id, renamed_at DESC)",
		"org_id     uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE",
		"user_id    uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE",
	}
	for _, marker := range required {
		if !strings.Contains(src, marker) {
			t.Fatalf("expected rename migration to contain %q", marker)
		}
	}
	for _, forbidden := range []string{
		"UNIQUE (from_slug)",
		"from_slug   text NOT NULL UNIQUE",
		"CREATE UNIQUE INDEX",
	} {
		if strings.Contains(renameSrc, forbidden) {
			t.Fatalf("rename history must not make historical slugs globally unique; found %q", forbidden)
		}
	}
}

func TestCurrentSlugColumnsRemainUnique(t *testing.T) {
	authSchema := readSource(t, "../migrations/postgres/001_auth_schema.up.sql")
	if !strings.Contains(authSchema, "username          public.citext UNIQUE") {
		t.Fatalf("profiles.users.username must remain unique")
	}
	if !strings.Contains(authSchema, "slug          text NOT NULL UNIQUE") {
		t.Fatalf("profiles.orgs.slug must remain unique")
	}
}

func TestOrgGetHandlerRedirectsHistoricalSlugButOwnerLookupReturnsJSON(t *testing.T) {
	orgsHandler := readSource(t, "../http/orgs_handlers.go")
	if !strings.Contains(orgsHandler, "w.WriteHeader(http.StatusMovedPermanently)") {
		t.Fatalf("GET /orgs/{org} should redirect historical slugs to canonical org path")
	}
	if !strings.Contains(orgsHandler, "strings.Replace(r.URL.Path, orgSlug, canonical, 1)") {
		t.Fatalf("GET /orgs/{org} should build a canonical redirect path")
	}
	ownersHandler := readSource(t, "../http/admin_reserved_accounts.go")
	start := strings.Index(ownersHandler, "func (s *Service) handleOwnerNamespaceInfoGET")
	end := strings.Index(ownersHandler, "func normalizeAdminAccountKind")
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("could not isolate handleOwnerNamespaceInfoGET source")
	}
	ownersHandler = ownersHandler[start:end]
	if strings.Contains(ownersHandler, "StatusMovedPermanently") || strings.Contains(ownersHandler, "http.Redirect") {
		t.Fatalf("GET /owners/{slug} should return canonical JSON, not HTTP redirects")
	}
	if !strings.Contains(ownersHandler, "LookupOwnerNamespace") {
		t.Fatalf("GET /owners/{slug} should use the canonical owner namespace lookup")
	}
	if !strings.Contains(ownersHandler, "Slug:          strings.TrimSpace(lookup.CanonicalSlug)") {
		t.Fatalf("GET /owners/{slug} should return the canonical slug in the top-level slug field")
	}
	if !strings.Contains(ownersHandler, "Username: strings.TrimSpace(lookup.User.Username)") {
		t.Fatalf("GET /owners/{slug} should include canonical username in JSON")
	}
	if !strings.Contains(ownersHandler, "Slug:        strings.TrimSpace(lookup.Org.Slug)") {
		t.Fatalf("GET /owners/{slug} should include canonical org slug in JSON")
	}
}

func TestRenameCooldownIsHardcodedSeventyTwoHours(t *testing.T) {
	src := readSource(t, "rename_policy.go")
	if !strings.Contains(src, "renameCooldown = 72 * time.Hour") {
		t.Fatalf("rename_policy.go must hardcode renameCooldown = 72 * time.Hour (issue #58)")
	}
}

func TestRenameReuseHoldIsHardcodedNinetyDays(t *testing.T) {
	src := readSource(t, "rename_policy.go")
	if !strings.Contains(src, "renameReuseHold = 90 * 24 * time.Hour") {
		t.Fatalf("rename_policy.go must hardcode renameReuseHold = 90 days")
	}
}

func TestOwnerSlugAvailabilityUsesIndexedRenameLookupWithReuseCutoff(t *testing.T) {
	src := readSource(t, "service_owner_namespace.go")
	start := strings.Index(src, "func (s *Service) ownerSlugAvailable")
	end := strings.Index(src, "func (s *Service) ensureOwnerSlugAvailable")
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("could not isolate ownerSlugAvailable source")
	}
	src = src[start:end]
	required := []string{
		"reuseCutoff := time.Now().UTC().Add(-renameReuseHold)",
		"WHERE r.from_slug=$1",
		"AND r.renamed_at >= $3",
		"JOIN profiles.users u ON u.id=r.user_id",
		"JOIN profiles.orgs o ON o.id=r.org_id",
	}
	for _, marker := range required {
		if !strings.Contains(src, marker) {
			t.Fatalf("expected owner slug availability to contain %q", marker)
		}
	}
	if strings.Contains(src, "lower(r.from_slug)=lower($1)") {
		t.Fatalf("owner slug availability should not wrap from_slug in lower(); it must use the from_slug index")
	}
	for _, marker := range []string{
		"JOIN profiles.users u ON u.id=r.user_id AND u.deleted_at IS NULL",
		"JOIN profiles.orgs o ON o.id=r.org_id AND o.deleted_at IS NULL",
	} {
		if strings.Contains(src, marker) {
			t.Fatalf("owner slug availability must keep soft-deleted owners reserved; found %q", marker)
		}
	}
}

func readSource(t *testing.T, path string) string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(src)
}

func sourceBetween(t *testing.T, src, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(src, startMarker)
	if start < 0 {
		t.Fatalf("could not find source marker %q", startMarker)
	}
	if endMarker == "" {
		return src[start:]
	}
	end := strings.Index(src[start+len(startMarker):], endMarker)
	if end < 0 {
		t.Fatalf("could not find source marker %q", endMarker)
	}
	return src[start : start+len(startMarker)+end]
}
