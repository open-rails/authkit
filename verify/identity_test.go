package verify

import (
	"testing"

	"github.com/open-rails/authkit/iam"
)

func TestBoundIdentity(t *testing.T) {
	group := &PermissionScope{GroupID: "g-1", AuthorityIssuer: "https://auth.test"}
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
		{name: "oauth client", cl: Claims{Kind: TokenOAuthClient, Issuer: "https://auth.test", ClientID: "worker", Subject: "worker", JOSEType: "at+jwt"}},
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
	native, _ := boundIdentity(Claims{Kind: TokenUser, Issuer: "https://auth.test", UserID: "user-9", SessionID: "s-9"})
	if s, _ := iam.StateOf(native); !s.IsUser() {
		t.Fatalf("a user's token = %v", s)
	} else if ref, bound := s.Session(); !bound || ref.SessionID != "s-9" {
		t.Fatal("a user's token is bound to its sign-in")
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
