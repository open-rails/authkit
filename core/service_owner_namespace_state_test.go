package core

import "testing"

func TestNormalizeOwnerNamespaceState(t *testing.T) {
	tests := []struct {
		in   OwnerNamespaceState
		want OwnerNamespaceState
	}{
		{in: OwnerNamespaceState(" RESTRICTED_NAME "), want: OwnerNamespaceStateRestrictedName},
		{in: OwnerNamespaceState(" RESERVED_NAME "), want: OwnerNamespaceStateRestrictedName},
		{in: OwnerNamespaceState("parked_org"), want: OwnerNamespaceStateParkedOrg},
		{in: OwnerNamespaceState("registered_org"), want: OwnerNamespaceStateRegistered},
		{in: OwnerNamespaceState("unknown"), want: ""},
	}
	for _, tc := range tests {
		got := normalizeOwnerNamespaceState(tc.in)
		if got != tc.want {
			t.Fatalf("normalizeOwnerNamespaceState(%q)=%q want=%q", tc.in, got, tc.want)
		}
	}
}

func TestValidateOwnerNamespaceState(t *testing.T) {
	if err := validateOwnerNamespaceState(OwnerNamespaceStateParkedOrg); err != nil {
		t.Fatalf("expected parked_org to be valid, got err=%v", err)
	}
	if err := validateOwnerNamespaceState(OwnerNamespaceStateRegistered); err != nil {
		t.Fatalf("expected registered_org to be valid, got err=%v", err)
	}
	if err := validateOwnerNamespaceState(OwnerNamespaceStateRestrictedName); err == nil {
		t.Fatalf("expected restricted_name to be rejected for org state")
	}
	if err := validateOwnerNamespaceState(OwnerNamespaceState("unknown")); err == nil {
		t.Fatalf("expected unknown state to be invalid")
	}
}
