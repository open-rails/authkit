package authhttp

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/open-rails/authkit/verify"

	jwt "github.com/golang-jwt/jwt/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
)

// memRemoteAppSource is a minimal in-memory RemoteApplicationSource for the
// verify layer.
type memRemoteAppSource struct {
	apps []authkit.RemoteApplication
}

func (m *memRemoteAppSource) ListEnabledRemoteApplications(_ context.Context) ([]authkit.RemoteApplication, error) {
	var out []authkit.RemoteApplication
	for _, a := range m.apps {
		if a.Enabled {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *memRemoteAppSource) GetRemoteApplication(_ context.Context, issuer string) (*authkit.RemoteApplication, error) {
	for i := range m.apps {
		if m.apps[i].Issuer == issuer {
			a := m.apps[i]
			return &a, nil
		}
	}
	return nil, errors.New("not_found")
}

// newDelegatedVerifier builds a Verifier trusting a single remote application.
func newDelegatedVerifier(t *testing.T, signer *jwtkit.RSASigner, iss string, aud []string) *verify.Verifier {
	t.Helper()
	v := verify.NewVerifier()

	if err := v.AddIssuer(iss, aud, verify.IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}); err != nil {
		t.Fatalf("AddIssuer: %v", err)
	}
	return v
}

func TestMintAndVerifyDelegatedAccessTokenBasic(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "host-kid")
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}
	tok, err := embedded.MintDelegatedAccessToken(context.Background(), signer, authkit.DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "user-123",
		Attributes:       map[string]any{"tier": "cozy_free"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	cl, err := newDelegatedVerifier(t, signer, iss, aud).Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cl.UserID != "" {
		t.Fatalf("expected empty UserID (no sub), got %q", cl.UserID)
	}
	if _, ok := cl.Delegated(); !ok {
		t.Fatal("expected delegated principal")
	}
	dp, ok := cl.Delegated()
	if !ok {
		t.Fatal("Delegated() returned !ok")
	}
	if dp.DelegatedSubject != "user-123" || dp.UserTier != "cozy_free" {
		t.Fatalf("principal=%+v", dp)
	}
}

func TestVerifyRejectsBothSubAndDelegatedSub(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "host-kid")
	iss := "https://cozy.example"
	now := time.Now()
	tok, err := signer.Sign(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"tensorhub"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"sub":           "local-1",
		"delegated_sub": "ext-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = newDelegatedVerifier(t, signer, iss, []string{"tensorhub"}).Verify(context.Background(), tok)
	if err == nil || err.Error() != "conflicting_subject" {
		t.Fatalf("expected conflicting_subject, got %v", err)
	}
}

func TestMintRequiresDelegatedSubject(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	if _, err := embedded.MintDelegatedAccessToken(context.Background(), signer, authkit.DelegatedAccessParams{Issuer: "x"}); err == nil {
		t.Fatal("expected error for missing delegated_sub")
	}
}

func TestNativeTokenIsNotDelegated(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss": iss,
		"aud": []string{"tensorhub"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"sub": "local-1",
	}, map[string]any{"typ": AccessTokenType})
	cl, err := newDelegatedVerifier(t, signer, iss, []string{"tensorhub"}).Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cl.Delegated(); ok {
		t.Fatal("native token should not be delegated")
	}
	if cl.UserID != "" || cl.Subject != "local-1" {
		t.Fatalf("external identity must stay issuer-qualified: %+v", cl.Principal())
	}
}

func TestVerifyRejectsAccessTokenWithoutAccessTyp(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.Sign(context.Background(), jwt.MapClaims{
		"iss": iss,
		"aud": []string{"tensorhub"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"sub": "local-1",
	})
	_, err := newDelegatedVerifier(t, signer, iss, []string{"tensorhub"}).Verify(context.Background(), tok)
	if err == nil || err.Error() != "access_token_wrong_typ" {
		t.Fatalf("expected access_token_wrong_typ, got %v", err)
	}
}

func TestVerifyRejectsDelegatedSubWithoutDelegatedTyp(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"tensorhub"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"delegated_sub": "ext-1",
	}, map[string]any{"typ": AccessTokenType})
	_, err := newDelegatedVerifier(t, signer, iss, []string{"tensorhub"}).Verify(context.Background(), tok)
	if err == nil || err.Error() != "delegated_access_wrong_typ" {
		t.Fatalf("expected delegated_access_wrong_typ, got %v", err)
	}
}

// TestIssuerOnlyDelegatedToken pins the issuer-only delegated-token contract.
func TestIssuerOnlyDelegatedToken(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "host-kid")
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://doujins.example"
	aud := []string{"openrails"}
	tok, err := embedded.MintDelegatedAccessToken(context.Background(), signer, authkit.DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "user-123",
		Permissions:      []string{"openrails:self:billing:read"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	v := newDelegatedVerifier(t, signer, iss, aud)
	_, dp, err := v.VerifyDelegatedAccess(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if dp.Issuer != iss || dp.DelegatedSubject != "user-123" {
		t.Fatalf("principal=%+v", dp)
	}
}

// TestDelegatedAccessRolesFromAttributes: attributes.roles UUIDs surface
// on DelegatedPrincipal.Roles + Claims.DelegatedRoles, in order; the native
// top-level Roles claim stays empty.
func TestDelegatedAccessRolesFromAttributes(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}
	u1 := "11111111-1111-1111-1111-111111111111"
	u2 := "22222222-2222-2222-2222-222222222222"

	tok, err := embedded.MintDelegatedAccessToken(context.Background(), signer, authkit.DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "user-123",
		Roles:            []string{u1, u2},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cl, dp, err := newDelegatedVerifier(t, signer, iss, aud).VerifyDelegatedAccess(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(dp.Roles) != 2 || dp.Roles[0] != u1 || dp.Roles[1] != u2 {
		t.Fatalf("principal Roles = %v", dp.Roles)
	}
	if len(cl.DelegatedRoles) != 2 || cl.DelegatedRoles[0] != u1 {
		t.Fatalf("claims DelegatedRoles = %v", cl.DelegatedRoles)
	}
	if len(cl.Roles) != 0 {
		t.Fatalf("native Claims.Roles should be empty on delegated token, got %v", cl.Roles)
	}
}

// TestDelegatedAccessRolesDropsMalformed: non-UUID/blank/non-string
// entries drop; valid UUIDs survive; the token is not failed.
func TestDelegatedAccessRolesDropsMalformed(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}
	good := "33333333-3333-3333-3333-333333333333"
	now := time.Now()

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

	_, dp, err := newDelegatedVerifier(t, signer, iss, aud).VerifyDelegatedAccess(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(dp.Roles) != 1 || dp.Roles[0] != good {
		t.Fatalf("Roles = %v, want [%s]", dp.Roles, good)
	}
}

// TestDelegatedAccessRolesCapped: more than maxDelegatedRoles UUIDs cap.
func TestDelegatedAccessRolesCapped(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}

	roles := make([]string, 0, verify.MaxDelegatedRoles+10)
	for i := 0; i < verify.MaxDelegatedRoles+10; i++ {
		roles = append(roles, delegatedUUIDForIndex(i))
	}
	tok, _ := embedded.MintDelegatedAccessToken(context.Background(), signer, authkit.DelegatedAccessParams{
		Issuer: iss, Audiences: aud, DelegatedSubject: "u1",
		Roles: roles, TTL: time.Minute,
	})
	_, dp, err := newDelegatedVerifier(t, signer, iss, aud).VerifyDelegatedAccess(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(dp.Roles) != verify.MaxDelegatedRoles {
		t.Fatalf("Roles len = %d, want cap %d", len(dp.Roles), verify.MaxDelegatedRoles)
	}
}

func delegatedUUIDForIndex(i int) string {
	const hex = "0123456789abcdef"
	b := []byte("00000000-0000-4000-8000-000000000000")
	b[len(b)-1] = hex[i&0xf]
	b[len(b)-2] = hex[(i>>4)&0xf]
	return string(b)
}

// TestVerifierRejectsUnregisteredIssuer: an issuer absent from the
// remote-application store is rejected even when its key would verify.
func TestVerifierRejectsUnregisteredIssuer(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	v := verify.NewVerifier()
	v.SetRemoteApplicationSource(&memRemoteAppSource{}) // empty store
	tok, _ := embedded.MintDelegatedAccessToken(context.Background(), signer, authkit.DelegatedAccessParams{
		Issuer: "https://rogue.example", Audiences: []string{"tensorhub"},
		DelegatedSubject: "x", TTL: time.Minute,
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected rejection of unregistered issuer")
	}
}
