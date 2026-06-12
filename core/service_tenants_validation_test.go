package core

import (
	"strings"
	"testing"
)

func TestValidateTenantSlug(t *testing.T) {
	t.Run("accepts basic slugs", func(t *testing.T) {
		for _, slug := range []string{
			"doujins",
			"cozy-creator",
			"a",
			"a0",
			"a-0",
			strings.Repeat("a", tenantSlugMaxLen),
		} {
			if err := validateTenantSlug(slug); err != nil {
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
			strings.Repeat("a", tenantSlugMaxLen+1),
		} {
			if err := validateTenantSlug(slug); err == nil {
				t.Fatalf("expected slug %q to be invalid", slug)
			}
		}
	})
}

func TestValidateTenantRole(t *testing.T) {
	t.Run("accepts safe roles", func(t *testing.T) {
		for _, role := range []string{
			"owner",
			"admin",
			"member",
			"tenant:billing_admin",
			"proj-read",
			"PROJ_WRITE",
			strings.Repeat("A", tenantRoleMaxLen),
		} {
			if err := validateTenantRole(role); err != nil {
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
			strings.Repeat("A", tenantRoleMaxLen+1),
		} {
			if err := validateTenantRole(role); err == nil {
				t.Fatalf("expected role %q to be invalid", role)
			}
		}
	})
}
