package core

import (
	"strings"
	"testing"
)

func TestValidateOrgSlug(t *testing.T) {
	t.Run("accepts basic slugs", func(t *testing.T) {
		for _, slug := range []string{
			"doujins",
			"cozy-creator",
			"a",
			"a0",
			"a-0",
			strings.Repeat("a", orgSlugMaxLen),
		} {
			if err := validateOrgSlug(slug); err != nil {
				t.Fatalf("expected slug %q to be valid, got err=%v", slug, err)
			}
		}
	})

	t.Run("rejects invalid slugs", func(t *testing.T) {
		for _, slug := range []string{
			"",
			"-abc",
			"abc-",
			"Abc",
			"abc_def",
			"abc.def",
			"abc/def",
			strings.Repeat("a", orgSlugMaxLen+1),
		} {
			if err := validateOrgSlug(slug); err == nil {
				t.Fatalf("expected slug %q to be invalid", slug)
			}
		}
	})
}

func TestValidateOrgRole(t *testing.T) {
	t.Run("accepts safe roles", func(t *testing.T) {
		for _, role := range []string{
			"owner",
			"admin",
			"member",
			"org:billing_admin",
			"proj-read",
			"PROJ_WRITE",
			strings.Repeat("A", orgRoleMaxLen),
		} {
			if err := validateOrgRole(role); err != nil {
				t.Fatalf("expected role %q to be valid, got err=%v", role, err)
			}
		}
	})

	t.Run("rejects invalid roles", func(t *testing.T) {
		for _, role := range []string{
			"",
			" ",
			"role with space",
			"role/with/slash",
			"role.with.dot",
			strings.Repeat("A", orgRoleMaxLen+1),
		} {
			if err := validateOrgRole(role); err == nil {
				t.Fatalf("expected role %q to be invalid", role)
			}
		}
	})
}
