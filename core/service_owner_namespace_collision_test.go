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
		"FROM profiles.user_slug_aliases a",
		"FROM profiles.orgs o",
		"FROM profiles.org_slug_aliases a",
	}
	for _, marker := range required {
		if !strings.Contains(code, marker) {
			t.Fatalf("expected owner namespace collision check to include %q", marker)
		}
	}
}
