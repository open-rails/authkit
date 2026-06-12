package authhttp

import (
	"context"
	"crypto"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// The slug-only delegated-token contract (HARD CUT): a delegated access token
// identifies the tenant by `tenant` (slug) + validated `iss` ONLY. A host
// knows its chosen slug the way a user knows their username; resource-account
// uuids are receiver-internal and never ride in tokens. Receivers pin their
// internal tenant record from the issuer registry and cross-check the slug;
// a token carrying a legacy `tenant_id` claim is rejected outright.

// TestSlugOnlyDelegatedToken: the canonical mint carries tenant + delegated_sub
// and no tenant_id; verification accepts it and the principal has no uuid.
func TestSlugOnlyDelegatedToken(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "host-kid")
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://doujins.example"
	aud := []string{"openrails"}
	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		Tenant:           "doujins",
		DelegatedSubject: "user-123",
		Permissions:      []string{"openrails:self:billing:read"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// The token must NOT carry a tenant_id claim at all.
	claims := jwt.MapClaims{}
	if _, _, perr := jwt.NewParser().ParseUnverified(tok, claims); perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	if _, present := claims["tenant_id"]; present {
		t.Fatalf("tenant_id claim present on minted token: %v", claims["tenant_id"])
	}
	if claims["tenant"] != "doujins" {
		t.Fatalf("tenant claim = %v, want doujins", claims["tenant"])
	}

	v := newDelegatedTestVerifier(t, signer, iss, aud)
	_, dp, err := v.VerifyDelegatedAccess(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if dp.Tenant != "doujins" || dp.DelegatedSubject != "user-123" {
		t.Fatalf("principal=%+v", dp)
	}
}

// TestDelegatedAccessRejectsTenantIDClaim: hard cut — a delegated token that
// still carries the legacy `tenant_id` uuid claim is rejected like any other
// forbidden claim on the profile.
func TestDelegatedAccessRejectsTenantIDClaim(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "host-kid")
	iss := "https://doujins.example"
	now := time.Now()
	tok, err := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"openrails"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"tenant":        "doujins",
		"tenant_id":     "0190dead-beef-7000-8000-000000000001",
		"delegated_sub": "user-123",
		"permissions":   []string{"openrails:self:billing:read"},
	}, map[string]any{"typ": DelegatedAccessTokenType})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = newDelegatedTestVerifier(t, signer, iss, []string{"openrails"}).VerifyDelegatedAccess(tok)
	if err == nil || err.Error() != "delegated_access_has_tenant_id" {
		t.Fatalf("err = %v, want delegated_access_has_tenant_id", err)
	}
}

// TestTrustedResourceAccountIsSlugOnly: the issuer-registry binding compares
// the registered resource account against the `tenant` slug claim — the only
// tenant identity a token carries.
func TestTrustedResourceAccountIsSlugOnly(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "host-kid")
	iss := "https://doujins.example"
	aud := []string{"openrails"}

	mint := func(tenant string) string {
		t.Helper()
		tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
			Issuer:           iss,
			Audiences:        aud,
			Tenant:           tenant,
			DelegatedSubject: "user-123",
			Permissions:      []string{"openrails:self:billing:read"},
			TTL:              time.Minute,
		})
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		return tok
	}
	verifier := func(trusted string) *Verifier {
		t.Helper()
		v := NewVerifier(WithTenantMode("multi"))
		if err := v.AddIssuer(iss, aud, IssuerOptions{
			RawKeys:                map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
			TrustedResourceAccount: trusted,
		}); err != nil {
			t.Fatalf("AddIssuer: %v", err)
		}
		return v
	}

	// Matching slug: accepted.
	if _, _, err := verifier("doujins").VerifyDelegatedAccess(mint("doujins")); err != nil {
		t.Fatalf("matching slug rejected: %v", err)
	}
	// One trusted issuer cannot claim another resource account.
	if _, _, err := verifier("doujins").VerifyDelegatedAccess(mint("other-tenant")); err == nil {
		t.Fatal("mismatched slug accepted")
	}
}
