package iam

import "testing"

func TestActor(t *testing.T) {
	for _, a := range []Actor{{}, UserActor(" "), APIKeyActor(""), RemoteApplicationActor(""), DelegatedActor(DelegatedGrant{Subject: "s"}), SystemActor().Within(Perm{"org:*"}), Actor{}.Within(Perm{"org:*"})} {
		if !a.IsZero() || a.Kind() != "" || a.String() != "invalid" {
			t.Fatalf("want the zero actor, got %v", a)
		}
	}
	op := SystemActor()
	if op.IsZero() || op.Kind() != ActorSystem || op.ID() != "" || op.Bounded() || !op.CeilingCovers(Perm{"root:users:ban"}) {
		t.Fatalf("system = %v", op)
	}
	u := UserActor(" user-1 ")
	if u.ID() != "user-1" || u.String() != "user:user-1" || u.Bounded() || !u.CeilingCovers(Perm{"org:members:manage"}) {
		t.Fatalf("user = %v", u)
	}
	// Within intersects: each ceiling must permit the permission.
	narrowed := u.Within(Perm{"org:members:*"}, Perm{"org:catalog:read"}).Within(Perm{"org:*:manage"})
	for perm, want := range map[Perm]bool{Perm{"org:members:manage"}: true, Perm{"org:catalog:read"}: false, Perm{"org:settings:manage"}: false, Perm{"repo:members:manage"}: false} {
		if got := narrowed.CeilingCovers(perm); got != want {
			t.Fatalf("CeilingCovers(%s) = %v, want %v", perm, got, want)
		}
	}
	if u.Bounded() || !u.CeilingCovers(Perm{"org:catalog:read"}) {
		t.Fatal("Within must not alias the receiver")
	}
	if nothing := u.Within(); !nothing.Bounded() || nothing.CeilingCovers(Perm{"org:members:read"}) {
		t.Fatal("an empty ceiling permits nothing")
	}
	grant := DelegatedGrant{Issuer: "https://auth.test", Subject: "user-2", Permissions: []Perm{Perm{"org:catalog:read"}}}
	d := DelegatedActor(grant)
	grant.Permissions[0] = Perm{"org:*"}
	g, ok := d.Delegation()
	if !ok || d.Kind() != ActorDelegated || d.ID() != "user-2" || g.Permissions[0] != (Perm{"org:catalog:read"}) || d.CeilingCovers(Perm{"org:catalog:write"}) {
		t.Fatalf("delegated = %v %+v", d, g)
	}
	if _, ok := u.Delegation(); ok {
		t.Fatal("a user actor has no delegation")
	}
}

func TestGroupRef(t *testing.T) {
	if !RootGroup().IsRoot() || RootGroup().ID() != "" || RootGroup().String() != "root" {
		t.Fatal("root reference")
	}
	id := GroupByID(" 0190e2b6-0000-7000-8000-000000000000 ")
	if id.ID() != "0190e2b6-0000-7000-8000-000000000000" || id.IsRoot() || id.IsZero() || id.String() != "id:0190e2b6-0000-7000-8000-000000000000" {
		t.Fatalf("id reference = %v", id)
	}
	if GroupByID("").IsRoot() || !GroupByID("").IsZero() {
		t.Fatal("an empty id addresses nothing")
	}
	if !(GroupRef{}).IsZero() || RootGroup().IsZero() {
		t.Fatal("zero reference")
	}
}
