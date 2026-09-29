package iam

import (
	"encoding/json"
	"testing"
)

// The text forms round-trip through JSON; decoding checks only the syntax.
func TestIdentifierText(t *testing.T) {
	type wire struct {
		Persona Persona
		Role    Role
		Perm    Perm
	}
	in := wire{Persona{"channel"}, Persona{"channel"}.OwnerRole(), Perm{"channel:posts:*"}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"Persona":"channel","Role":"channel:owner","Perm":"channel:posts:*"}` {
		t.Fatalf("encoded %s", raw)
	}
	var out wire
	if err := json.Unmarshal(raw, &out); err != nil || out != in {
		t.Fatalf("decoded %+v, %v", out, err)
	}
	if err := json.Unmarshal([]byte(`{"Persona":"","Role":"","Perm":""}`), &out); err != nil || out != (wire{}) {
		t.Fatalf("empty text is the zero value: %+v, %v", out, err)
	}
	for _, bad := range []string{
		`{"Persona":"Channel"}`, `{"Persona":"a:b"}`,
		`{"Role":"moderator"}`, `{"Role":"channel:"}`, `{"Role":"channel:mod:x"}`,
		`{"Perm":"*"}`, `{"Perm":"channel"}`, `{"Perm":"channel:"}`, `{"Perm":"*:posts:edit"}`, `{"Perm":"Channel:posts:edit"}`, `{"Perm":"a::b"}`,
	} {
		if err := json.Unmarshal([]byte(bad), &out); err == nil {
			t.Errorf("%s decoded", bad)
		}
	}
	if r := (Persona{"org"}).OwnerRole(); !r.IsOwner() || r.Name() != "owner" || r.Persona() != (Persona{"org"}) || r.String() != "org:owner" {
		t.Fatalf("owner role %v", r)
	}
}
