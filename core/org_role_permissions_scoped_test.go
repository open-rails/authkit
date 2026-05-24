package core

import (
	"context"
	"testing"
)

// TestValidateGrant_ResourceScopedPrefix covers #46 resource-scoped grants:
// a "<resource>:<action>:<name>" permission is valid when its
// "<resource>:<action>" base is in the catalog (the app interprets <name>).
// Uses actorAll=true so only the catalog/prefix validation runs (no DB).
func TestValidateGrant_ResourceScopedPrefix(t *testing.T) {
	svc := NewService(Options{
		PermissionCatalog: []PermissionDef{
			{Name: "repo:read"}, {Name: "repo:write"}, {Name: "endpoint:invoke"},
		},
	}, Keyset{})
	ctx := context.Background()

	cases := []struct {
		tok         string
		wantUnknown bool
	}{
		{"repo:read", false},              // exact catalog hit
		{"repo:write:my-model", false},    // scoped; base repo:write in catalog
		{"endpoint:invoke:my-llm", false}, // scoped; base endpoint:invoke in catalog
		{"repo:read:a/b", false},          // name with a slash is fine
		{"repo:bogus", true},              // not in catalog
		{"repo:bogus:x", true},            // scoped base repo:bogus not in catalog
		{"dataset:read:x", true},          // scoped base dataset:read not in catalog
	}
	for _, c := range cases {
		unknown, _, err := svc.ValidateGrant(ctx, "org", "actor", []string{c.tok}, true)
		if err != nil {
			t.Fatalf("%s: ValidateGrant err: %v", c.tok, err)
		}
		if got := len(unknown) > 0; got != c.wantUnknown {
			t.Errorf("%s: unknown=%v, want %v (unknown=%v)", c.tok, got, c.wantUnknown, unknown)
		}
	}
}
