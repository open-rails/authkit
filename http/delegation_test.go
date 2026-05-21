package authhttp

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

func newDelegatedTestVerifier(t *testing.T, signer *jwtkit.RSASigner, iss string, aud []string) *Verifier {
	t.Helper()
	v := NewVerifier(WithOrgMode("multi"))
	if err := v.AddIssuer(iss, aud, IssuerOptions{
		RawKeys: map[string]*rsa.PublicKey{signer.KID(): signer.PublicKey()},
	}); err != nil {
		t.Fatalf("AddIssuer: %v", err)
	}
	return v
}

func TestMintAndVerifyDelegatedToken(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}
	tok, err := MintDelegatedToken(context.Background(), signer, DelegatedTokenParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "user-123",
		Tenant:           "cozy-art",
		UserTier:         "cozy_free",
		Roles:            []string{"member"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	cl, err := newDelegatedTestVerifier(t, signer, iss, aud).Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cl.UserID != "" {
		t.Fatalf("expected empty UserID (no sub), got %q", cl.UserID)
	}
	if !cl.IsDelegated() {
		t.Fatal("expected IsDelegated")
	}
	dp, ok := cl.Delegated()
	if !ok {
		t.Fatal("Delegated() returned !ok")
	}
	if dp.Tenant != "cozy-art" || dp.DelegatedSubject != "user-123" || dp.UserTier != "cozy_free" {
		t.Fatalf("principal=%+v", dp)
	}
	if len(dp.Roles) != 1 || dp.Roles[0] != "member" {
		t.Fatalf("roles=%v", dp.Roles)
	}
}

func TestVerifyRejectsBothSubAndDelegatedSub(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "platform-kid")
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
	_, err = newDelegatedTestVerifier(t, signer, iss, []string{"tensorhub"}).Verify(tok)
	if err == nil || err.Error() != "conflicting_subject" {
		t.Fatalf("expected conflicting_subject, got %v", err)
	}
}

func TestMintRequiresDelegatedSubject(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	if _, err := MintDelegatedToken(context.Background(), signer, DelegatedTokenParams{Issuer: "x"}); err == nil {
		t.Fatal("expected error for missing delegated_sub")
	}
}

func TestNativeTokenIsNotDelegated(t *testing.T) {
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
	cl, err := newDelegatedTestVerifier(t, signer, iss, []string{"tensorhub"}).Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if cl.IsDelegated() {
		t.Fatal("native token should not be delegated")
	}
	if cl.UserID != "local-1" {
		t.Fatalf("UserID=%q", cl.UserID)
	}
}
