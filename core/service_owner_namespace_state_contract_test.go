package core

import (
	"os"
	"strings"
	"testing"
)

func TestGetOwnerNamespaceStateBySlugChecksReservedNamesBeforeOrgResolve(t *testing.T) {
	src, err := os.ReadFile("service_owner_namespace_state.go")
	if err != nil {
		t.Fatalf("read service_owner_namespace_state.go: %v", err)
	}
	code := string(src)
	restrictedIdx := strings.Index(code, "SELECT EXISTS(SELECT 1 FROM profiles.owner_reserved_names")
	resolveIdx := strings.Index(code, "ResolveOrgBySlug")
	if restrictedIdx < 0 {
		t.Fatalf("expected restricted-name existence check in GetOwnerNamespaceStateBySlug")
	}
	if resolveIdx < 0 {
		t.Fatalf("expected ResolveOrgBySlug call in GetOwnerNamespaceStateBySlug")
	}
	if restrictedIdx > resolveIdx {
		t.Fatalf("expected restricted-name check to run before org resolution")
	}
}

func TestParkOrgNamespaceCreatesOrgWithoutUserPlaceholder(t *testing.T) {
	src, err := os.ReadFile("service_owner_namespace_state.go")
	if err != nil {
		t.Fatalf("read service_owner_namespace_state.go: %v", err)
	}
	code := string(src)
	if !strings.Contains(code, "INSERT INTO profiles.orgs (slug, metadata)") {
		t.Fatalf("expected parked-org promotion to create org record")
	}
	if strings.Contains(code, "INSERT INTO profiles.users") {
		t.Fatalf("parked-org promotion should not require creating same-slug login users")
	}
}

func TestPromoteParkedOrgToRegisteredCanGrantOwnerMembership(t *testing.T) {
	src, err := os.ReadFile("service_owner_namespace_state.go")
	if err != nil {
		t.Fatalf("read service_owner_namespace_state.go: %v", err)
	}
	code := string(src)
	if !strings.Contains(code, "s.AddMember(ctx, org.Slug, ownerUserID)") {
		t.Fatalf("expected parked->registered transition to grant membership when owner user provided")
	}
	if !strings.Contains(code, "s.AssignRole(ctx, org.Slug, ownerUserID, orgOwnerRole)") {
		t.Fatalf("expected parked->registered transition to grant owner role when owner user provided")
	}
	if !strings.Contains(code, "if ownerUserID == \"\" {\n\t\treturn \"\", ErrOwnerMembershipRequired") {
		t.Fatalf("expected parked->registered transition to require owner membership input")
	}
	if !strings.Contains(code, "countActiveOrgOwners") {
		t.Fatalf("expected parked->registered transition to verify owner membership invariant")
	}
}

func TestTransitionContractCoversValidAndInvalidStatePaths(t *testing.T) {
	src, err := os.ReadFile("service_owner_namespace_state.go")
	if err != nil {
		t.Fatalf("read service_owner_namespace_state.go: %v", err)
	}
	code := string(src)

	// Direct transition helper must explicitly handle all canonical states.
	requiredStateCases := []string{
		"case OwnerNamespaceStateRestrictedName:",
		"case OwnerNamespaceStateParkedOrg:",
		"case OwnerNamespaceStateRegistered:",
	}
	for _, marker := range requiredStateCases {
		if !strings.Contains(code, marker) {
			t.Fatalf("expected transition handler to include %q", marker)
		}
	}

	// Invalid state / transition paths must return deterministic errors.
	requiredErrors := []string{
		"ErrInvalidOwnerNamespaceTransition",
		"ErrInvalidOwnerNamespaceState",
	}
	for _, marker := range requiredErrors {
		if !strings.Contains(code, marker) {
			t.Fatalf("expected transition contract to include %q guards", marker)
		}
	}
}
