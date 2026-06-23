package authcore

import "testing"

// grantsCoverAll is the heart of #136 no-escalation: an actor may grant a role
// only if it already holds every permission that role confers. These cases are
// pure over resolved grant sets (no DB).
func TestGrantsCoverAll_NoEscalation(t *testing.T) {
	owner := []string{"root:*"}
	admin := []string{"root:users:ban", "root:content:moderate", "root:admin-console:access"}
	weak := []string{"root:users:ban"}

	cases := []struct {
		name   string
		actor  []string
		target []string
		want   bool
	}{
		{"owner covers owner", owner, owner, true},
		{"owner covers admin", owner, admin, true},
		{"owner covers weak", owner, weak, true},
		{"admin covers itself (equal level ok)", admin, admin, true},
		{"admin covers weak subset", admin, weak, true},
		{"admin CANNOT cover owner (root:*)", admin, owner, false},
		{"weak CANNOT cover admin (more perms)", weak, admin, false},
		{"weak covers itself", weak, weak, true},
		{"weak CANNOT cover owner", weak, owner, false},
		{"nobody covers empty actor -> non-empty target", nil, weak, false},
		{"empty target is vacuously covered", weak, nil, true},
	}
	for _, tc := range cases {
		if got := grantsCoverAll(tc.actor, tc.target); got != tc.want {
			t.Errorf("%s: grantsCoverAll(%v, %v) = %v, want %v", tc.name, tc.actor, tc.target, got, tc.want)
		}
	}
}

// PermMatches treats `ns:*` (two segments) as the namespace-wide glob; a
// resource-scoped glob like `root:users:*` is a literal 3-segment grant whose
// last segment is `*`, and it covers `root:users:ban`. Verify that path so the
// subset check behaves for resource-scoped admin bundles.
func TestGrantsCoverAll_ResourceGlob(t *testing.T) {
	holder := []string{"root:users:*"} // matches root:users:<action>
	if !grantsCoverAll(holder, []string{"root:users:ban"}) {
		t.Fatalf("root:users:* should cover root:users:ban")
	}
	if grantsCoverAll(holder, []string{"root:content:moderate"}) {
		t.Fatalf("root:users:* must NOT cover root:content:moderate")
	}
	if grantsCoverAll(holder, []string{"root:*"}) {
		t.Fatalf("root:users:* must NOT cover the owner grant root:*")
	}
}
