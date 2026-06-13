package authhttp

import (
	"context"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// TestDelegatedAccessRolesFromAttributes: a delegated token whose
// attributes.roles is a JSON array of UUID strings surfaces those UUIDs on
// DelegatedPrincipal.Roles (and Claims.DelegatedRoles), preserving order.
func TestDelegatedAccessRolesFromAttributes(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "k")
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}
	u1 := "11111111-1111-1111-1111-111111111111"
	u2 := "22222222-2222-2222-2222-222222222222"

	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "user-123",
		Roles:            []string{u1, u2},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	v := newDelegatedTestVerifier(t, signer, iss, aud)
	cl, dp, err := v.VerifyDelegatedAccess(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(dp.Roles) != 2 || dp.Roles[0] != u1 || dp.Roles[1] != u2 {
		t.Fatalf("principal Roles = %v, want [%s %s]", dp.Roles, u1, u2)
	}
	if len(cl.DelegatedRoles) != 2 || cl.DelegatedRoles[0] != u1 {
		t.Fatalf("claims DelegatedRoles = %v", cl.DelegatedRoles)
	}
	// The typed Roles convenience must NOT leak a top-level roles claim.
	if len(cl.Roles) != 0 {
		t.Fatalf("native Claims.Roles should be empty on delegated token, got %v", cl.Roles)
	}
}

// TestDelegatedAccessRolesDropsMalformed: non-UUID and blank entries are
// dropped; well-formed UUIDs survive — the whole token is not failed.
func TestDelegatedAccessRolesDropsMalformed(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}
	good := "33333333-3333-3333-3333-333333333333"
	now := time.Now()

	// Hand-build so we can inject malformed entries the mint path wouldn't drop
	// (mint only trims blanks; UUID validation is a verify-side guarantee).
	tok, err := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           aud,
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"delegated_sub": "u1",
		"attributes": map[string]any{
			"roles": []any{"not-a-uuid", good, "", 42, "GHIJKLMN-0000-0000-0000-000000000000"},
		},
	}, map[string]any{"typ": DelegatedAccessTokenType})
	if err != nil {
		t.Fatal(err)
	}

	_, dp, err := newDelegatedTestVerifier(t, signer, iss, aud).VerifyDelegatedAccess(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(dp.Roles) != 1 || dp.Roles[0] != good {
		t.Fatalf("Roles = %v, want [%s] (malformed dropped)", dp.Roles, good)
	}
}

// TestDelegatedAccessRolesAbsent: a token without attributes.roles yields an
// empty Roles surface — backward compatible, no behavior change.
func TestDelegatedAccessRolesAbsent(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}

	tok, _ := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer: iss, Audiences: aud, DelegatedSubject: "u1",
		Attributes: map[string]any{"tier": "cozy_free"}, TTL: time.Minute,
	})
	_, dp, err := newDelegatedTestVerifier(t, signer, iss, aud).VerifyDelegatedAccess(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(dp.Roles) != 0 {
		t.Fatalf("expected empty Roles, got %v", dp.Roles)
	}
}

// TestDelegatedAccessRolesCapped: more than maxDelegatedRoles UUIDs are capped.
func TestDelegatedAccessRolesCapped(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}

	roles := make([]string, 0, maxDelegatedRoles+10)
	for i := 0; i < maxDelegatedRoles+10; i++ {
		roles = append(roles, uuidForIndex(i))
	}
	tok, _ := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer: iss, Audiences: aud, DelegatedSubject: "u1",
		Roles: roles, TTL: time.Minute,
	})
	_, dp, err := newDelegatedTestVerifier(t, signer, iss, aud).VerifyDelegatedAccess(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(dp.Roles) != maxDelegatedRoles {
		t.Fatalf("Roles len = %d, want cap %d", len(dp.Roles), maxDelegatedRoles)
	}
}

// uuidForIndex produces a deterministic well-formed UUID string for testing.
func uuidForIndex(i int) string {
	const hex = "0123456789abcdef"
	b := []byte("00000000-0000-4000-8000-000000000000")
	// Patch the last two nibbles from i (enough for our small counts).
	b[len(b)-1] = hex[i&0xf]
	b[len(b)-2] = hex[(i>>4)&0xf]
	return string(b)
}
