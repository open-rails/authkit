package authhttp

// AK-C1: Self-asserted global_roles from a federated (remote_application) issuer
// must not grant platform global-admin.
//
// The fix tags the platform's own issuer as isLocal=true in issuerEntry. For all
// other issuers (remote_application / federated), extractClaims strips
// global_roles / org_roles / roles before returning Claims, so a merchant who
// controls their JWKS endpoint cannot mint a token that passes claimsHasGlobalAdmin.

import (
	"context"
	"crypto"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// mintAccessToken signs a minimal access+jwt with arbitrary extra claims.
func mintAccessJWT(t *testing.T, signer *jwtkit.RSASigner, iss string, extra gjwt.MapClaims) string {
	t.Helper()
	now := time.Now()
	claims := gjwt.MapClaims{
		"iss": iss,
		"sub": "attacker-uid",
		"aud": []string{"platform"},
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	tok, err := signer.SignWithHeaders(context.Background(), claims, map[string]any{"typ": AccessTokenType})
	if err != nil {
		t.Fatalf("mintAccessJWT: %v", err)
	}
	return tok
}

// TestGlobalRolesStrippedForFederatedIssuer is the core AK-C1 regression test.
// A remote_application issuer (IsLocal=false) that self-asserts global_roles:["admin"]
// must have those claims stripped on verify — claimsHasGlobalAdmin must return false.
func TestGlobalRolesStrippedForFederatedIssuer(t *testing.T) {
	platformSigner, _ := jwtkit.NewRSASigner(2048, "platform-kid")
	attackerSigner, _ := jwtkit.NewRSASigner(2048, "attacker-kid")

	platformIss := "https://platform.example"
	attackerIss := "https://attacker.example"

	ver := NewVerifier(WithAlgorithms("RS256"))
	_ = ver.AddIssuer(platformIss, []string{"platform"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{platformSigner.KID(): platformSigner.PublicKey()},
		IsLocal: true,
	})
	_ = ver.AddIssuer(attackerIss, []string{"platform"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{attackerSigner.KID(): attackerSigner.PublicKey()},
		// IsLocal intentionally omitted (false) — this is a remote_application issuer
	})

	extra := gjwt.MapClaims{"global_roles": []any{"admin"}}

	// Attacker token: global_roles must be stripped.
	attackerTok := mintAccessJWT(t, attackerSigner, attackerIss, extra)
	cl, err := ver.Verify(attackerTok)
	if err != nil {
		t.Fatalf("Verify attacker token: %v", err)
	}
	if len(cl.GlobalRoles) != 0 {
		t.Errorf("AK-C1: federated issuer global_roles not stripped: %v", cl.GlobalRoles)
	}
	if claimsHasGlobalAdmin(cl) {
		t.Error("AK-C1: claimsHasGlobalAdmin returned true for federated issuer token — exploit still works")
	}
}

// TestGlobalRolesRetainedForLocalIssuer ensures the fix doesn't break the
// legitimate path: the platform's own signer can still issue tokens whose
// global_roles claim is honoured.
func TestGlobalRolesRetainedForLocalIssuer(t *testing.T) {
	platformSigner, _ := jwtkit.NewRSASigner(2048, "platform-kid")
	platformIss := "https://platform.example"

	ver := NewVerifier(WithAlgorithms("RS256"))
	_ = ver.AddIssuer(platformIss, []string{"platform"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{platformSigner.KID(): platformSigner.PublicKey()},
		IsLocal: true,
	})

	tok := mintAccessJWT(t, platformSigner, platformIss, gjwt.MapClaims{
		"global_roles": []any{"admin"},
	})
	cl, err := ver.Verify(tok)
	if err != nil {
		t.Fatalf("Verify platform token: %v", err)
	}
	if len(cl.GlobalRoles) == 0 {
		t.Error("platform signer global_roles unexpectedly stripped — legitimate admin flow broken")
	}
	if !claimsHasGlobalAdmin(cl) {
		t.Error("claimsHasGlobalAdmin returned false for platform signer — admin gate broken")
	}
}

// TestOrgRolesAndRolesStrippedForFederatedIssuer checks that org_roles and roles
// are also stripped — not just global_roles — so a federated issuer can't gain
// org-scoped authority either.
func TestOrgRolesAndRolesStrippedForFederatedIssuer(t *testing.T) {
	attackerSigner, _ := jwtkit.NewRSASigner(2048, "attacker-kid")
	attackerIss := "https://attacker.example"

	ver := NewVerifier(WithAlgorithms("RS256"))
	_ = ver.AddIssuer(attackerIss, []string{"platform"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{attackerSigner.KID(): attackerSigner.PublicKey()},
	})

	tok := mintAccessJWT(t, attackerSigner, attackerIss, gjwt.MapClaims{
		"org_roles":    []any{"owner"},
		"global_roles": []any{"admin"},
	})
	cl, err := ver.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(cl.GlobalRoles) != 0 {
		t.Errorf("global_roles not stripped: %v", cl.GlobalRoles)
	}
	if len(cl.OrgRoles) != 0 {
		t.Errorf("org_roles not stripped: %v", cl.OrgRoles)
	}
	if len(cl.Roles) != 0 {
		t.Errorf("roles not stripped: %v", cl.Roles)
	}
}

// TestFederatedIssuerDefaultIsNotLocal verifies the fail-safe: an issuer
// registered via AddIssuer without IsLocal:true defaults to federated (not local),
// so any future dynamically-registered remote_application is sandboxed by default.
func TestFederatedIssuerDefaultIsNotLocal(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "kid")
	iss := "https://merchant.example"

	ver := NewVerifier(WithAlgorithms("RS256"))
	_ = ver.AddIssuer(iss, []string{"platform"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
		// IsLocal not set — default is false
	})

	tok := mintAccessJWT(t, signer, iss, gjwt.MapClaims{"global_roles": []any{"admin"}})
	cl, err := ver.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claimsHasGlobalAdmin(cl) {
		t.Error("default (non-local) issuer passed claimsHasGlobalAdmin — IsLocal must default to false")
	}
}
