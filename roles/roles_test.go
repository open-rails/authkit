package roles

import "testing"

func TestIDFromSlug_GoldenIDs(t *testing.T) {
	tests := []struct {
		name string
		slug string
		want string
	}{
		{"owner", "owner", "aa854a1c-6864-57de-a615-4d9ea2c3a8fa"},
		{"admin", "admin", "38eefc83-abe7-5cb9-bc5f-6ad2d9ccc1a9"},
		{"member", "member", "80bd537e-5b2e-57d1-9fae-f67c16b0bf87"},
		{"support", "support", "a64923e9-124d-5b3d-9a4b-b795cb470994"},
		{"viewer", "viewer", "3be549c8-d7ab-543f-8576-f15451967338"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IDFromSlug(tt.slug).String()
			if got != tt.want {
				t.Errorf("IDFromSlug(%q) = %q, want %q", tt.slug, got, tt.want)
			}
		})
	}
}

func TestIDFromSlug_Deterministic(t *testing.T) {
	a := IDFromSlug("owner")
	b := IDFromSlug("owner")
	if a != b {
		t.Errorf("IDFromSlug(\"owner\") is not deterministic: first=%q second=%q", a, b)
	}
}

func TestIDFromSlug_DistinctSlugs(t *testing.T) {
	owner := IDFromSlug("owner")
	admin := IDFromSlug("admin")
	if owner == admin {
		t.Errorf("IDFromSlug(\"owner\") == IDFromSlug(\"admin\"); expected distinct UUIDs")
	}
}

func TestNamespaceRoleIDs_Pinned(t *testing.T) {
	want := "ef5d0f45-83c6-5dbe-b15a-e017bc88ab5a"
	got := NamespaceRoleIDs.String()
	if got != want {
		t.Errorf("NamespaceRoleIDs = %q, want %q", got, want)
	}
}
