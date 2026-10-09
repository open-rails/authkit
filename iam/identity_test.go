package iam

import (
	"encoding/json"
	"testing"

	"github.com/open-rails/helpers/auth"
)

func TestIdentityState(t *testing.T) {
	for _, id := range []auth.Identity{{}, UserIdentity(" "), APIKeyIdentity(""), ApplicationIdentity(""),
		Within(SystemIdentity(), Perm{"org:*"}), Within(auth.Identity{}, Perm{"org:*"}), PinnedTo(SystemIdentity(), "g-1")} {
		if s, ok := StateOf(id); ok || !s.IsZero() || s.String() != "invalid" {
			t.Fatalf("want no state, got %v", s)
		}
	}
	op, ok := StateOf(SystemIdentity())
	if !ok || !op.IsSystem() || op.ID() != "" || op.Bounded() || !op.CeilingCovers(Perm{"root:users:ban"}) || op.String() != "system" {
		t.Fatalf("system = %v", op)
	}
	user := UserIdentity(" user-1 ")
	u, _ := StateOf(user)
	if !u.IsUser() || u.ID() != "user-1" || u.String() != "user:user-1" || u.Bounded() || !u.CeilingCovers(Perm{"org:members:manage"}) {
		t.Fatalf("user = %v", u)
	}
	if user.Subject != "user-1" || user.SubjectKind != auth.SubjectUser || !user.SelfInvoked() || user.Credential.Kind != CredentialSystem {
		t.Fatalf("user identity = %+v", user)
	}
	// Within intersects: each ceiling must permit the permission.
	narrowed, _ := StateOf(Within(Within(user, Perm{"org:members:*"}, Perm{"org:catalog:read"}), Perm{"org:*:manage"}))
	for perm, want := range map[Perm]bool{{"org:members:manage"}: true, {"org:catalog:read"}: false, {"org:settings:manage"}: false, {"repo:members:manage"}: false} {
		if got := narrowed.CeilingCovers(perm); got != want {
			t.Fatalf("CeilingCovers(%s) = %v, want %v", perm, got, want)
		}
	}
	if u, _ := StateOf(user); u.Bounded() || !u.CeilingCovers(Perm{"org:catalog:read"}) {
		t.Fatal("Within must not alias the identity it narrows")
	}
	if nothing, _ := StateOf(Within(user)); !nothing.Bounded() || nothing.CeilingCovers(Perm{"org:members:read"}) {
		t.Fatal("an empty ceiling permits nothing")
	}

	app := PinnedTo(ApplicationIdentity("app-1"), "g-1")
	if a, _ := StateOf(app); !a.IsApplication() || a.ID() != "app-1" || a.Group() != "g-1" {
		t.Fatalf("an application pinned to its group = %v", a)
	}
	if _, ok := StateOf(PinnedTo(app, "g-2")); ok {
		t.Fatal("a pin only narrows: pinned to g-1, it cannot move to g-2")
	}
	if p, ok := StateOf(PinnedTo(app, "g-1")); !ok || p.Group() != "g-1" {
		t.Fatal("pinning to the same group keeps it")
	}

	bound := InSession(user, SessionRef{SessionID: "s-1"})
	if s, ok := StateOf(bound); !ok || !s.IsUser() {
		t.Fatal("a user binds to its session")
	} else if ref, ok := s.Session(); !ok || ref.SessionID != "s-1" {
		t.Fatal("session lost")
	}
	if _, ok := StateOf(InSession(ApplicationIdentity("app-1"), SessionRef{SessionID: "s-1"})); ok {
		t.Fatal("an application has no sign-in to bind")
	}
	key, _ := StateOf(APIKeyIdentity("key-1"))
	if !key.IsAPIKey() || key.IsApplication() || key.ID() != "key-1" {
		t.Fatalf("api key = %v", key)
	}
}

// An Identity grants only through AuthKit's state: one built or decoded from
// data has none, whatever its fields claim.
func TestIdentityFromDataHasNoState(t *testing.T) {
	system := SystemIdentity()
	for name, id := range map[string]auth.Identity{
		"zero":           {},
		"literal user":   {Issuer: "https://auth.test", Subject: "user-1", SubjectKind: auth.SubjectUser, Invoker: auth.Invoker{Issuer: "https://auth.test", ID: "user-1"}, Credential: auth.Credential{Kind: auth.CredentialSession, ID: "s-1"}},
		"literal system": {Credential: auth.Credential{Kind: CredentialSystem}},
		"foreign state":  {Credential: auth.Credential{Kind: CredentialSystem}.WithState(&struct{ system bool }{true})},
		"zero state":     {Credential: auth.Credential{Kind: CredentialSystem}.WithState(&CredentialState{})},
	} {
		if _, ok := StateOf(id); ok {
			t.Fatalf("%s: grants", name)
		}
	}
	b, err := json.Marshal(system)
	if err != nil {
		t.Fatal(err)
	}
	var decoded auth.Identity
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Credential.Kind != CredentialSystem || decoded.Credential.State() != nil {
		t.Fatalf("encoding kept the state: %+v", decoded)
	}
	if _, ok := StateOf(decoded); ok {
		t.Fatal("a decoded system identity grants")
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
