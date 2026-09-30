package iam

import (
	"encoding/json"
	"os"
	"testing"
)

// permVector is one case of testdata/perm_vectors.json. The auth-ui
// TypeScript matcher runs the same file (auth-ui/src/client/permissions.test.ts).
type permVector struct {
	Grant      string `json:"grant"`
	Permission string `json:"permission"`
	Matches    bool   `json:"matches"`
}

func TestPermMatchesVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/perm_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []permVector
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	grants := map[string][]Perm{}
	covered := map[string]bool{}
	for _, v := range vectors {
		if got := (Perm{v.Permission}).Matches(Perm{v.Grant}); got != v.Matches {
			t.Errorf("Perm(%q).Matches(%q) = %v, want %v", v.Permission, v.Grant, got, v.Matches)
		}
		grants[v.Permission] = append(grants[v.Permission], Perm{v.Grant})
		covered[v.Permission] = covered[v.Permission] || v.Matches
	}
	for perm, gs := range grants {
		if got := AnyGrantCovers(gs, Perm{perm}); got != covered[perm] {
			t.Errorf("AnyGrantCovers(%q, %q) = %v, want %v", gs, perm, got, covered[perm])
		}
	}
}
