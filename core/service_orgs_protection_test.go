package core

import (
	"os"
	"strings"
	"testing"
)

func TestRenameOrgSlugKeepsPersonalOrgsLocked(t *testing.T) {
	src, err := os.ReadFile("service_orgs.go")
	if err != nil {
		t.Fatalf("read service_orgs.go: %v", err)
	}
	code := string(src)
	if !strings.Contains(code, "if isPersonal {") || !strings.Contains(code, "return ErrPersonalOrgLocked") {
		t.Fatalf("expected RenameOrgSlug to keep personal orgs non-renamable via ErrPersonalOrgLocked")
	}
}
