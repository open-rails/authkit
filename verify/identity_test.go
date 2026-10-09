package verify

import (
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/helpers/auth"
)

func TestBoundIdentity(t *testing.T) {
	group := &PermissionScope{GroupID: "g-1", AuthorityIssuer: "https://auth.test"}
	remote := Claims{Kind: TokenRemoteApplication, Issuer: "https://app.test", RemoteApplicationID: "app-1", Permissions: []string{"org:members:*"}, Group: group}
	delegated := Claims{Kind: TokenDelegated, Issuer: "https://app.test", DelegatedSubject: "u_9", Permissions: []string{"org:posts:read"},
		RemoteApplicationID: "app-2", SessionID: "s-9", Group: &PermissionScope{GroupID: "g-2", AuthorityIssuer: "https://auth.test"}}
	cases := []struct {
		name    string
		cl      Claims
		subject string
		id      string
	}{
		{name: "native user", cl: Claims{Kind: TokenUser, Issuer: "https://auth.test", UserID: "user-1", SessionID: "s-1"}, subject: "user-1", id: "user-1"},
		{name: "device key user", cl: Claims{Kind: TokenUser, Issuer: "https://auth.test", UserID: "user-1", DeviceKeyID: "dk-1"}, subject: "user-1", id: "user-1"},
		{name: "external user", cl: Claims{Kind: TokenUser, Subject: "ext-1", Issuer: "https://idp.test"}},
		{name: "enrollment-only token", cl: Claims{Kind: TokenUser, Issuer: "https://auth.test", UserID: "user-1", TwoFAEnrollment: true}},
		{name: "api key", cl: Claims{Kind: TokenAPIKey, APIKeyID: "key-1", Group: group}, subject: "g-1", id: "key-1"},
		{name: "api key without id", cl: Claims{Kind: TokenAPIKey, Group: group}},
		{name: "remote application", cl: remote, subject: "app-1", id: "app-1"},
		{name: "remote application without id", cl: Claims{Kind: TokenRemoteApplication, Issuer: "https://app.test", Group: group}},
		{name: "an application's delegation", cl: delegated, subject: "app-2", id: "app-2"},
		{name: "no kind", cl: Claims{Issuer: "https://auth.test", UserID: "user-1"}},
		{name: "empty", cl: Claims{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := boundIdentity(tc.cl)
			s, bound := iam.StateOf(id)
			if ok != (tc.id != "") || ok != bound || id.Subject != tc.subject || s.ID() != tc.id {
				t.Fatalf("boundIdentity = (%+v, %v), state %v; want subject %q id %q", id, ok, s, tc.subject, tc.id)
			}
			if s.IsSystem() {
				t.Fatal("claims must never yield the system")
			}
		})
	}

	id, _ := boundIdentity(remote)
	if s, _ := iam.StateOf(id); !s.Bounded() || !s.CeilingCovers(ident.Perm("org:members:manage")) || s.CeilingCovers(ident.Perm("org:settings:manage")) {
		t.Fatal("remote application token permissions must be its ceiling")
	}
	id, _ = boundIdentity(delegated)
	s, _ := iam.StateOf(id)
	if !s.IsApplication() || !s.Delegated() || s.Group() != "g-2" || !s.CeilingCovers(ident.Perm("org:posts:read")) || s.CeilingCovers(ident.Perm("org:posts:delete")) {
		t.Fatalf("an application's delegation = %v", s)
	}
	if id.Invoker != (auth.Invoker{Issuer: "https://app.test", ID: "u_9"}) {
		t.Fatalf("its user invokes it: %+v", id.Invoker)
	}
	if _, bound := s.Session(); bound {
		t.Fatal("an application's delegation carries no AuthKit session")
	}
	native, _ := boundIdentity(Claims{Kind: TokenDelegated, Issuer: "https://auth.test", DelegatedSubject: "user-9", SessionID: "s-9"})
	if s, _ := iam.StateOf(native); !s.Delegated() || s.DelegatedIssuer() != "https://auth.test" {
		t.Fatalf("AuthKit's delegation of a user = %v", s)
	} else if ref, bound := s.Session(); !bound || ref.SessionID != "s-9" {
		t.Fatal("AuthKit's own delegation is bound to the minting session")
	}
	if native.Subject != "user-9" || !native.SelfInvoked() {
		t.Fatalf("AuthKit's delegation of a user is the user: %+v", native)
	}
}

// Claims a host stores with SetClaims describe the request but grant
// nothing: their identity carries no AuthKit state.
func TestSetClaimsIdentityGrantsNothing(t *testing.T) {
	ctx := SetClaims(t.Context(), Claims{Kind: TokenUser, Issuer: "https://auth.test", UserID: "user-1", SessionID: "s-1"})
	id, ok := IdentityFromContext(ctx)
	if !ok || id.Subject != "user-1" {
		t.Fatalf("identity = %+v, %v", id, ok)
	}
	if _, bound := iam.StateOf(id); bound {
		t.Fatal("SetClaims' identity grants")
	}
}
