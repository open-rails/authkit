package iam

import "testing"

func TestActor(t *testing.T) {
	for _, a := range []Actor{{}, UserActor(" "), APIKeyActor(""), RemoteApplicationActor(""), DelegatedActor(DelegatedGrant{Subject: "s"}), OperatorActor().Within("org:*"), Actor{}.Within("org:*")} {
		if !a.IsZero() || a.Kind() != "" || a.String() != "invalid" {
			t.Fatalf("want the zero actor, got %v", a)
		}
	}
	op := OperatorActor()
	if op.IsZero() || op.Kind() != ActorOperator || op.ID() != "" || op.Bounded() || !op.CeilingCovers("root:users:ban") {
		t.Fatalf("operator = %v", op)
	}
	u := UserActor(" user-1 ")
	if u.ID() != "user-1" || u.String() != "user:user-1" || u.Bounded() || !u.CeilingCovers("org:members:manage") {
		t.Fatalf("user = %v", u)
	}
	// Within intersects: each ceiling must permit the permission.
	narrowed := u.Within("org:members:*", "org:catalog:read").Within("org:*:manage")
	for perm, want := range map[Perm]bool{"org:members:manage": true, "org:catalog:read": false, "org:settings:manage": false, "repo:members:manage": false} {
		if got := narrowed.CeilingCovers(perm); got != want {
			t.Fatalf("CeilingCovers(%s) = %v, want %v", perm, got, want)
		}
	}
	if u.Bounded() || !u.CeilingCovers("org:catalog:read") {
		t.Fatal("Within must not alias the receiver")
	}
	if nothing := u.Within(); !nothing.Bounded() || nothing.CeilingCovers("org:members:read") {
		t.Fatal("an empty ceiling permits nothing")
	}
	grant := DelegatedGrant{Issuer: "https://auth.test", Subject: "user-2", Permissions: []Perm{"org:catalog:read"}}
	d := DelegatedActor(grant)
	grant.Permissions[0] = "org:*"
	g, ok := d.Delegation()
	if !ok || d.Kind() != ActorDelegated || d.ID() != "user-2" || g.Permissions[0] != "org:catalog:read" || d.CeilingCovers("org:catalog:write") {
		t.Fatalf("delegated = %v %+v", d, g)
	}
	if _, ok := u.Delegation(); ok {
		t.Fatal("a user actor has no delegation")
	}
}

func TestGroupRef(t *testing.T) {
	if !RootGroup().IsRoot() || !GroupBySlug(" root ", "ignored").IsRoot() || GroupBySlug("root", "x").Slug() != "" {
		t.Fatal("root reference")
	}
	g := GroupBySlug(" org ", " Acme ")
	if g.Persona() != "org" || g.Slug() != "acme" || g.ID() != "" || g.IsRoot() || g.String() != "org/acme" {
		t.Fatalf("slug reference = %v", g)
	}
	id := GroupByID(" 0190e2b6-0000-7000-8000-000000000000 ")
	if id.ID() != "0190e2b6-0000-7000-8000-000000000000" || id.Persona() != "" || id.IsRoot() || id.IsZero() {
		t.Fatalf("id reference = %v", id)
	}
	if !(GroupRef{}).IsZero() || RootGroup().IsZero() {
		t.Fatal("zero reference")
	}
}
