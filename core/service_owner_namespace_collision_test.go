package core

import (
	"os"
	"strings"
	"testing"
)

func TestOwnerSlugAvailabilityChecksSharedUserOrgNamespace(t *testing.T) {
	src, err := os.ReadFile("service_owner_namespace.go")
	if err != nil {
		t.Fatalf("read service_owner_namespace.go: %v", err)
	}
	code := string(src)

	required := []string{
		"FROM profiles.owner_reserved_names r",
		"FROM profiles.users u",
		// Issue #58: rename history lives in *_renames now (not *_slug_aliases).
		"FROM profiles.user_renames r",
		"FROM profiles.orgs o",
		"FROM profiles.org_renames r",
	}
	for _, marker := range required {
		if !strings.Contains(code, marker) {
			t.Fatalf("expected owner namespace collision check to include %q", marker)
		}
	}
}
