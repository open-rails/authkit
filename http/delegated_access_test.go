package authhttp

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// TestMintAndVerifyDelegatedAccessToken exercises the canonical contract: typ
// header, tenant/delegated_sub, permissions, attributes, no sub.
func TestMintAndVerifyDelegatedAccessToken(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://cozy.example"
	aud := []string{"openrails"}
	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		Tenant:           "cozy-art",
		DelegatedSubject: "user-123",
		Permissions:      []string{"openrails:self:billing:read", "openrails:self:checkout:create"},
		Attributes:       map[string]any{"tier": "cozy_free", "budget": 42},
		TTL:              time.Minute,
		JTI:              "tok-1",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// JOSE header carries typ=delegated-access+jwt.
	tokObj, _, perr := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	if typ, _ := tokObj.Header["typ"].(string); typ != DelegatedAccessTokenType {
		t.Fatalf("typ header = %q, want %q", typ, DelegatedAccessTokenType)
	}

	v := newDelegatedTestVerifier(t, signer, iss, aud)
	cl, dp, err := v.VerifyDelegatedAccess(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cl.UserID != "" {
		t.Fatalf("expected empty UserID (no sub), got %q", cl.UserID)
	}
	if !cl.IsDelegatedAccessToken() {
		t.Fatal("expected IsDelegatedAccessToken")
	}
	if dp.Tenant != "cozy-art" || dp.DelegatedSubject != "user-123" {
		t.Fatalf("principal=%+v", dp)
	}
	if dp.JTI != "tok-1" {
		t.Fatalf("jti=%q", dp.JTI)
	}
	if len(dp.Permissions) != 2 || dp.Permissions[0] != "openrails:self:billing:read" {
		t.Fatalf("permissions=%v", dp.Permissions)
	}
	if !cl.HasPermission("openrails:self:checkout:create") {
		t.Fatal("expected HasPermission")
	}
}

// TestDelegatedAccessRejectsNormalSub: a typ=delegated-access+jwt token MUST
// NOT carry `sub`.
func TestDelegatedAccessRejectsNormalSub(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, err := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"openrails"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"tenant":        "cozy-art",
		"delegated_sub": "ext-1",
		"sub":           "local-1",
	}, map[string]any{"typ": DelegatedAccessTokenType})
	if err != nil {
		t.Fatal(err)
	}
	_, err = newDelegatedTestVerifier(t, signer, iss, []string{"openrails"}).Verify(tok)
	if err == nil {
		t.Fatal("expected rejection of service token with sub")
	}
	// Either invariant may fire (both sub+delegated_sub here); both are rejects.
	if err.Error() != "conflicting_subject" && err.Error() != "access_token_has_sub" {
		t.Fatalf("unexpected error %v", err)
	}
}

// TestDelegatedAccessRejectsSubOnlyAccessToken: a typ=delegated-access+jwt
// token with ONLY a normal sub (no delegated_sub) must still be rejected by the
// typ invariant.
func TestDelegatedAccessRejectsSubOnlyAccessToken(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":    iss,
		"aud":    []string{"openrails"},
		"iat":    now.Unix(),
		"exp":    now.Add(time.Minute).Unix(),
		"tenant": "cozy-art",
		"sub":    "local-1",
	}, map[string]any{"typ": DelegatedAccessTokenType})
	_, err := newDelegatedTestVerifier(t, signer, iss, []string{"openrails"}).Verify(tok)
	if err == nil || err.Error() != "access_token_has_sub" {
		t.Fatalf("expected access_token_has_sub, got %v", err)
	}
}

// TestDelegatedAccessRejectsSubPlusDelegatedSub covers the explicit
// both-subjects reject for a delegated service token (no typ header path).
func TestDelegatedAccessRejectsSubPlusDelegatedSub(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.Sign(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"openrails"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"sub":           "local-1",
		"delegated_sub": "ext-1",
	})
	_, err := newDelegatedTestVerifier(t, signer, iss, []string{"openrails"}).Verify(tok)
	if err == nil || err.Error() != "conflicting_subject" {
		t.Fatalf("expected conflicting_subject, got %v", err)
	}
}

func TestDelegatedAccessRejectsTenantClaim(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"openrails"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"tenant":        "cozy-art",
		"org":           "cozy-art",
		"delegated_sub": "ext-1",
	}, map[string]any{"typ": DelegatedAccessTokenType})
	_, err := newDelegatedTestVerifier(t, signer, iss, []string{"openrails"}).Verify(tok)
	if err == nil || err.Error() != "delegated_access_has_org" {
		t.Fatalf("expected delegated_access_has_org, got %v", err)
	}
}

func TestDelegatedAccessRejectsIssuerTenantMismatch(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://doujins.example"
	aud := []string{"openrails"}

	v := NewVerifier()
	if err := v.AddIssuer(iss, aud, IssuerOptions{
		RawKeys:                rawKey(signer),
		TrustedResourceAccount: "doujins",
	}); err != nil {
		t.Fatal(err)
	}

	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		Tenant:           "hentai0",
		DelegatedSubject: "paul-fidika",
		Permissions:      []string{"openrails:tenant:admin"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = v.VerifyDelegatedAccess(tok)
	if err == nil || err.Error() != "resource_account_issuer_mismatch" {
		t.Fatalf("expected resource_account_issuer_mismatch, got %v", err)
	}
}

func TestDelegatedAccessRejectsMissingTenant(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"openrails"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"delegated_sub": "ext-1",
	}, map[string]any{"typ": DelegatedAccessTokenType})
	_, err := newDelegatedTestVerifier(t, signer, iss, []string{"openrails"}).Verify(tok)
	if err == nil || err.Error() != "missing_tenant" {
		t.Fatalf("expected missing_tenant, got %v", err)
	}
}

// TestDelegatedAccessRoundTripsArbitraryAttributes: arbitrary JSON survives.
func TestDelegatedAccessRoundTripsArbitraryAttributes(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	aud := []string{"openrails"}
	attrs := map[string]any{
		"tier":       "cozy_pro",
		"budget":     1000,
		"risk":       map[string]any{"bucket": "low", "score": 0.12},
		"flags":      []any{"a", "b"},
		"enterprise": true,
	}
	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		Tenant:           "cozy-art",
		DelegatedSubject: "u1",
		Attributes:       attrs,
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	cl, err := newDelegatedTestVerifier(t, signer, iss, aud).Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	raw, ok := cl.Attribute("risk")
	if !ok {
		t.Fatal("missing risk attribute")
	}
	var risk struct {
		Bucket string  `json:"bucket"`
		Score  float64 `json:"score"`
	}
	if err := json.Unmarshal(raw, &risk); err != nil {
		t.Fatalf("unmarshal risk: %v", err)
	}
	if risk.Bucket != "low" || risk.Score != 0.12 {
		t.Fatalf("risk=%+v", risk)
	}
	if cl.UserTier != "cozy_pro" {
		t.Fatalf("UserTier from attributes.tier = %q", cl.UserTier)
	}
}

func TestDelegatedAccessRejectsTopLevelUserTier(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"tensorhub"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"tenant":        "cozy-art",
		"delegated_sub": "u1",
		"user_tier":     "legacy_free",
		"attributes":    map[string]any{"tier": "canonical_pro"},
	}, map[string]any{"typ": DelegatedAccessTokenType})
	_, err := newDelegatedTestVerifier(t, signer, iss, []string{"tensorhub"}).Verify(tok)
	if err == nil || err.Error() != "delegated_access_has_user_tier" {
		t.Fatalf("expected delegated_access_has_user_tier, got %v", err)
	}
}

func TestDelegatedAccessRejectsRolesClaim(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"openrails"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"tenant":        "cozy-art",
		"delegated_sub": "u1",
		"roles":         []string{"admin", "superuser"},
	}, map[string]any{"typ": DelegatedAccessTokenType})
	_, err := newDelegatedTestVerifier(t, signer, iss, []string{"openrails"}).Verify(tok)
	if err == nil || err.Error() != "delegated_access_has_roles" {
		t.Fatalf("expected delegated_access_has_roles, got %v", err)
	}
}

// TestPermissionCatalogValidator rejects tokens with unknown permissions.
func TestPermissionCatalogValidator(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	aud := []string{"openrails"}
	catalog := map[string]bool{"openrails:self:billing:read": true}
	v := NewVerifier(
		WithPermissionCatalog(func(perms []string) error {
			for _, p := range perms {
				if !catalog[p] {
					return errors.New("unknown_permission")
				}
			}
			return nil
		}),
	)
	if err := v.AddIssuer(iss, aud, IssuerOptions{RawKeys: rawKey(signer)}); err != nil {
		t.Fatal(err)
	}

	// Good token: only catalog perms.
	good, _ := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer: iss, Audiences: aud, Tenant: "t", DelegatedSubject: "u",
		Permissions: []string{"openrails:self:billing:read"}, TTL: time.Minute,
	})
	if _, _, err := v.VerifyDelegatedAccess(good); err != nil {
		t.Fatalf("good token rejected: %v", err)
	}

	// Bad token: a permission not in the catalog.
	bad, _ := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer: iss, Audiences: aud, Tenant: "t", DelegatedSubject: "u",
		Permissions: []string{"openrails:tenant:admin"}, TTL: time.Minute,
	})
	if _, _, err := v.VerifyDelegatedAccess(bad); err == nil {
		t.Fatal("expected unknown_permission rejection")
	}
}

// TestAttributesPolicyValidator rejects tokens whose attributes violate policy.
func TestAttributesPolicyValidator(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	aud := []string{"openrails"}
	v := NewVerifier(
		WithAttributesPolicy(func(attrs map[string]json.RawMessage) error {
			if _, ok := attrs["tier"]; !ok {
				return errors.New("tier_required")
			}
			return nil
		}),
	)
	if err := v.AddIssuer(iss, aud, IssuerOptions{RawKeys: rawKey(signer)}); err != nil {
		t.Fatal(err)
	}
	bad, _ := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer: iss, Audiences: aud, Tenant: "t", DelegatedSubject: "u", TTL: time.Minute,
	})
	if _, _, err := v.VerifyDelegatedAccess(bad); err == nil {
		t.Fatal("expected tier_required rejection")
	}
	good, _ := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer: iss, Audiences: aud, Tenant: "t", DelegatedSubject: "u",
		Attributes: map[string]any{"tier": "cozy_free"}, TTL: time.Minute,
	})
	if _, _, err := v.VerifyDelegatedAccess(good); err != nil {
		t.Fatalf("good token rejected: %v", err)
	}
}

func rawKey(s jwtkit.PublicKeySigner) map[string]crypto.PublicKey {
	return map[string]crypto.PublicKey{s.KID(): s.PublicKey()}
}
