package verify

import (
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
)

func TestActorFromClaims(t *testing.T) {
	remote := Claims{Kind: iam.ActorRemoteApplication, RemoteApplicationID: "app-1", Permissions: []string{"org:members:*"}}
	delegated := Claims{Kind: iam.ActorDelegated, Issuer: "https://auth.test", DelegatedSubject: "user-9", Permissions: []string{"org:posts:read"},
		RemoteApplicationID: "app-2", SessionID: "s-9", Group: &PermissionScope{GroupID: "g-2"}}
	cases := []struct {
		name string
		cl   Claims
		kind iam.ActorKind
		id   string
	}{
		{name: "native user", cl: Claims{Kind: iam.ActorUser, UserID: "user-1"}, kind: iam.ActorUser, id: "user-1"},
		{name: "device key user", cl: Claims{Kind: iam.ActorUser, UserID: "user-1", DeviceKeyID: "dk-1"}, kind: iam.ActorUser, id: "user-1"},
		{name: "external user", cl: Claims{Kind: iam.ActorUser, Subject: "ext-1", Issuer: "https://idp.test"}},
		{name: "enrollment-only token", cl: Claims{Kind: iam.ActorUser, UserID: "user-1", TwoFAEnrollment: true}},
		{name: "api key", cl: Claims{Kind: iam.ActorAPIKey, APIKeyID: "key-1"}, kind: iam.ActorAPIKey, id: "key-1"},
		{name: "api key without id", cl: Claims{Kind: iam.ActorAPIKey}},
		{name: "remote application", cl: remote, kind: iam.ActorRemoteApplication, id: "app-1"},
		{name: "remote application without id", cl: Claims{Kind: iam.ActorRemoteApplication}},
		{name: "delegated", cl: delegated, kind: iam.ActorDelegated, id: "user-9"},
		{name: "no kind", cl: Claims{UserID: "user-1"}},
		{name: "empty", cl: Claims{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, ok := ActorFromClaims(tc.cl)
			if ok != (tc.kind != "") || a.Kind() != tc.kind || a.ID() != tc.id {
				t.Fatalf("ActorFromClaims = (%v, %v), want kind %q id %q", a, ok, tc.kind, tc.id)
			}
			if a.Kind() == iam.ActorSystem {
				t.Fatal("claims must never yield the system")
			}
		})
	}

	a, _ := ActorFromClaims(remote)
	if !a.Bounded() || !a.CeilingCovers(ident.Perm("org:members:manage")) || a.CeilingCovers(ident.Perm("org:settings:manage")) {
		t.Fatal("remote application token permissions must be the actor's ceiling")
	}
	d, _ := ActorFromClaims(delegated)
	g, ok := d.Delegation()
	if !ok || g.Issuer != "https://auth.test" || g.RemoteApplicationID != "app-2" || g.GroupID != "g-2" || !d.CeilingCovers(ident.Perm("org:posts:read")) || d.CeilingCovers(ident.Perm("org:posts:delete")) {
		t.Fatalf("delegated grant = %+v", g)
	}
	if _, bound := d.Session(); bound {
		t.Fatal("an application's delegation carries no AuthKit session")
	}
	native, _ := ActorFromClaims(Claims{Kind: iam.ActorDelegated, Issuer: "https://auth.test", DelegatedSubject: "user-9", SessionID: "s-9"})
	if s, bound := native.Session(); !bound || s.SessionID != "s-9" {
		t.Fatal("AuthKit's own delegation is bound to the minting session")
	}
}
