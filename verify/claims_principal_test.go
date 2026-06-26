package verify

import (
	"testing"

	authkit "github.com/open-rails/authkit"
)

func TestClaimsPrincipalKindAndIsUser(t *testing.T) {
	cases := []struct {
		name string
		cl   Claims
		kind authkit.PrincipalKind
		user bool
	}{
		{name: "user", cl: Claims{UserID: "user-1"}, kind: authkit.PrincipalKindUser, user: true},
		{name: "api key", cl: Claims{UserID: "not-a-user", TokenType: APIKeyPrincipalType}, kind: authkit.PrincipalKindAPIKey},
		{name: "remote app", cl: Claims{TokenType: RemoteApplicationTokenType}, kind: authkit.PrincipalKindRemoteApplication},
		{name: "delegated", cl: Claims{DelegatedSubject: "worker-1"}, kind: authkit.PrincipalKindDelegated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cl.PrincipalKind(); got != tc.kind {
				t.Fatalf("kind = %q, want %q", got, tc.kind)
			}
			if got := tc.cl.IsUser(); got != tc.user {
				t.Fatalf("IsUser = %v, want %v", got, tc.user)
			}
		})
	}
}
