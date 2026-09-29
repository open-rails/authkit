package verify

import (
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/jwtkit"
)

func TestActorFromClaims(t *testing.T) {
	remote := Claims{TokenType: RemoteApplicationTokenType, TokenTyp: jwtkit.RemoteApplicationAccessTokenType, RemoteApplicationID: "app-1", Permissions: []string{"org:members:*"}}
	delegated := Claims{Issuer: "https://auth.test", TokenTyp: jwtkit.DelegatedAccessTokenType, DelegatedSubject: "user-9", Permissions: []string{"org:posts:read"}, RemoteApplicationID: "app-2", PermissionGroupID: "g-2"}
	cases := []struct {
		name    string
		cl      Claims
		kind    iam.ActorKind
		id      string
		machine bool
	}{
		{name: "native user", cl: Claims{UserID: "user-1"}, kind: iam.ActorUser, id: "user-1"},
		{name: "device key user", cl: Claims{UserID: "user-1", DeviceKeyID: "dk-1"}, kind: iam.ActorUser, id: "user-1"},
		{name: "external user", cl: Claims{Subject: "ext-1", Issuer: "https://idp.test"}},
		{name: "api key", cl: Claims{UserID: "not-a-user", TokenType: APIKeyPrincipalType, APIKeyID: "key-1"}, kind: iam.ActorAPIKey, id: "key-1", machine: true},
		{name: "api key without id", cl: Claims{TokenType: APIKeyPrincipalType}, machine: true},
		{name: "remote application", cl: remote, kind: iam.ActorRemoteApplication, id: "app-1", machine: true},
		{name: "remote application wrong typ", cl: Claims{TokenType: RemoteApplicationTokenType, RemoteApplicationID: "app-1"}, machine: true},
		{name: "remote application with user", cl: Claims{TokenType: RemoteApplicationTokenType, TokenTyp: jwtkit.RemoteApplicationAccessTokenType, RemoteApplicationID: "app-1", UserID: "u"}, machine: true},
		{name: "delegated", cl: delegated, kind: iam.ActorDelegated, id: "user-9", machine: true},
		{name: "delegated without typ", cl: Claims{Issuer: "https://auth.test", DelegatedSubject: "user-9"}, machine: true},
		{name: "empty", cl: Claims{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, ok := ActorFromClaims(tc.cl)
			if ok != (tc.kind != "") || a.Kind() != tc.kind || a.ID() != tc.id {
				t.Fatalf("ActorFromClaims = (%v, %v), want kind %q id %q", a, ok, tc.kind, tc.id)
			}
			if a.Kind() == iam.ActorOperator {
				t.Fatal("claims must never yield an operator")
			}
			if got := tc.cl.IsMachine(); got != tc.machine {
				t.Fatalf("IsMachine = %v, want %v", got, tc.machine)
			}
		})
	}

	a, _ := ActorFromClaims(remote)
	if !a.Bounded() || !a.CeilingCovers("org:members:manage") || a.CeilingCovers("org:settings:manage") {
		t.Fatal("remote application token permissions must be the actor's ceiling")
	}
	d, _ := ActorFromClaims(delegated)
	g, ok := d.Delegation()
	if !ok || g.Issuer != "https://auth.test" || g.RemoteApplicationID != "app-2" || g.GroupID != "g-2" || !d.CeilingCovers("org:posts:read") || d.CeilingCovers("org:posts:delete") {
		t.Fatalf("delegated grant = %+v", g)
	}
}
