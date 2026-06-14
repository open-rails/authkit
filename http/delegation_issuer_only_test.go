package authhttp

import (
	"context"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// The issuer-only delegated-token contract (HARD CUT): a delegated access
// token carries `delegated_sub` (the host's stable user uuid) and NO org
// claims of any kind — the VALIDATED `iss` IS the org identity. The
// receiver's issuer registry maps the issuer to exactly one internal org
// record (slug + uuid), so neither identifier ever rides in the token: a
// host's complete identity is its issuer URL and signing key. Tokens carrying
// the legacy `org` or `org_id` claims are rejected outright.

// TestIssuerOnlyDelegatedToken: the canonical mint carries delegated_sub and
// neither org claim; verification accepts it.
func TestIssuerOnlyDelegatedToken(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "host-kid")
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://doujins.example"
	aud := []string{"openrails"}
	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "user-123",
		Permissions:      []string{"openrails:self:billing:read"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// The token must carry NEITHER org claim (absent, not empty).
	claims := jwt.MapClaims{}
	if _, _, perr := jwt.NewParser().ParseUnverified(tok, claims); perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	for _, forbidden := range []string{"org", "org_id"} {
		if _, present := claims[forbidden]; present {
			t.Fatalf("%s claim present on minted token: %v", forbidden, claims[forbidden])
		}
	}

	v := newDelegatedTestVerifier(t, signer, iss, aud)
	_, dp, err := v.VerifyDelegatedAccess(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if dp.Issuer != iss || dp.DelegatedSubject != "user-123" {
		t.Fatalf("principal=%+v", dp)
	}
}

// TestDelegatedAccessRejectsOrgIDClaim: a token carrying the legacy
// `org_id` uuid claim is rejected. (The `org` slug rejection is covered
// by TestDelegatedAccessRejectsOrgClaim in delegated_access_test.go.)
func TestDelegatedAccessRejectsOrgIDClaim(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "host-kid")
	iss := "https://doujins.example"
	now := time.Now()
	tok, err := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"openrails"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"org_id":        "0190dead-beef-7000-8000-000000000001",
		"delegated_sub": "user-123",
		"permissions":   []string{"openrails:self:billing:read"},
	}, map[string]any{"typ": DelegatedAccessTokenType})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = newDelegatedTestVerifier(t, signer, iss, []string{"openrails"}).VerifyDelegatedAccess(tok)
	if err == nil || err.Error() != "delegated_access_has_org_id" {
		t.Fatalf("err = %v, want delegated_access_has_org_id", err)
	}
}
