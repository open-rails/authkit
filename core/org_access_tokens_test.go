package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestOATMarker(t *testing.T) {
	if got := OATMarker(""); got != "oat_" {
		t.Fatalf("empty prefix marker = %q, want %q", got, "oat_")
	}
	if got := OATMarker("cozy"); got != "cozy_oat_" {
		t.Fatalf("branded marker = %q, want %q", got, "cozy_oat_")
	}
	if got := OATMarker("  cozy  "); got != "cozy_oat_" {
		t.Fatalf("trimmed marker = %q, want %q", got, "cozy_oat_")
	}
}

func TestFormatParseOATRoundTrip(t *testing.T) {
	cases := []struct{ prefix, keyID, secret string }{
		{"", "abc123KEYID00000", "SECRETvalue123base62"},
		{"cozy", "abc123KEYID00000", "SECRETvalue123base62"},
	}
	for _, tc := range cases {
		full := FormatOAT(tc.prefix, tc.keyID, tc.secret)
		if !HasOATPrefix(tc.prefix, full) {
			t.Fatalf("HasOATPrefix(%q, %q) = false", tc.prefix, full)
		}
		keyID, secret, ok := ParseOAT(tc.prefix, full)
		if !ok {
			t.Fatalf("ParseOAT(%q, %q) ok=false", tc.prefix, full)
		}
		if keyID != tc.keyID || secret != tc.secret {
			t.Fatalf("round-trip mismatch: got (%q,%q) want (%q,%q)", keyID, secret, tc.keyID, tc.secret)
		}
	}
}

func TestParseOATRejects(t *testing.T) {
	cases := []struct {
		name, prefix, token string
	}{
		{"no marker", "", "not-a-token"},
		{"jwt-looking", "cozy", "eyJhbGciOi.payload.sig"},
		{"wrong prefix", "cozy", "other_oat_key_secret"},
		{"missing secret", "", "oat_keyonly"},
		{"empty secret", "", "oat_key_"},
		{"empty key", "", "oat__secret"},
	}
	for _, tc := range cases {
		if _, _, ok := ParseOAT(tc.prefix, tc.token); ok {
			t.Errorf("%s: ParseOAT(%q,%q) ok=true, want false", tc.name, tc.prefix, tc.token)
		}
	}
}

func TestRandBase62(t *testing.T) {
	s, err := randBase62(43)
	if err != nil {
		t.Fatalf("randBase62: %v", err)
	}
	if len(s) != 43 {
		t.Fatalf("len = %d, want 43", len(s))
	}
	for _, r := range s {
		if !strings.ContainsRune(base62Alphabet, r) {
			t.Fatalf("non-base62 rune %q in %q", r, s)
		}
	}
	// Two draws should differ with overwhelming probability.
	s2, _ := randBase62(43)
	if s == s2 {
		t.Fatalf("two random draws were identical: %q", s)
	}
}

func TestValidTokenPrefix(t *testing.T) {
	cases := []struct {
		prefix string
		valid  bool
	}{
		{"", true},
		{"cozy", true},
		{"abc123", true},
		{"sixteencharspre0", true},   // exactly 16
		{"seventeenchars000", false}, // 17
		{"Cozy", false},              // uppercase
		{"co-zy", false},             // hyphen
		{"co_zy", false},             // underscore
		{"co zy", false},             // space
	}
	for _, tc := range cases {
		if got := validTokenPrefix(tc.prefix); got != tc.valid {
			t.Errorf("validTokenPrefix(%q) = %v, want %v", tc.prefix, got, tc.valid)
		}
	}
}

// TestOrgAccessTokenLifecycle exercises mint -> resolve -> list -> revoke ->
// rejected against a real database. Skips when AUTHKIT_TEST_DATABASE_URL is
// unset. created_by is left nil (audit-only, ON DELETE SET NULL) so the test
// needs no user fixture.
func TestOrgAccessTokenLifecycle(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test", TokenPrefix: "cozy"}, Keyset{}).WithPostgres(pool)

	const slug = "oat-lifecycle-test"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	var orgID string
	if err := pool.QueryRow(ctx, `INSERT INTO profiles.orgs (slug) VALUES ($1) RETURNING id::text`, slug).Scan(&orgID); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE id=$1::uuid`, orgID) })

	// Mint.
	tok, plaintext, err := svc.MintOrgAccessToken(ctx, slug, "ci-token", []string{"deployer"}, "", nil)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !strings.HasPrefix(plaintext, "cozy_oat_") {
		t.Fatalf("token %q lacks branded marker", plaintext)
	}
	keyID, secret, ok := ParseOAT("cozy", plaintext)
	if !ok || keyID != tok.KeyID {
		t.Fatalf("ParseOAT recovered (%q,ok=%v), want key %q", keyID, ok, tok.KeyID)
	}

	// Resolve success.
	gotOrg, gotScopes, err := svc.ResolveOrgAccessToken(ctx, keyID, secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if gotOrg != slug {
		t.Fatalf("resolve org = %q, want %q", gotOrg, slug)
	}
	if len(gotScopes) != 1 || gotScopes[0] != "deployer" {
		t.Fatalf("resolve scopes = %v, want [deployer]", gotScopes)
	}

	// Wrong secret + unknown key_id are both invalid_token (no info leak).
	if _, _, err := svc.ResolveOrgAccessToken(ctx, keyID, "wrongsecret"); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("wrong secret err = %v, want ErrInvalidAccessToken", err)
	}
	if _, _, err := svc.ResolveOrgAccessToken(ctx, "nonexistentkey0", secret); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("unknown key err = %v, want ErrInvalidAccessToken", err)
	}

	// List returns metadata only (the struct has no secret field).
	list, err := svc.ListOrgAccessTokens(ctx, slug)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].Name != "ci-token" || list[0].KeyID != tok.KeyID {
		t.Fatalf("list = %+v", list)
	}

	// Expiry rejection (force past expiry).
	if _, err := pool.Exec(ctx, `UPDATE profiles.org_access_tokens SET expires_at=now()-interval '1 hour' WHERE id=$1::uuid`, tok.ID); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if _, _, err := svc.ResolveOrgAccessToken(ctx, keyID, secret); !errors.Is(err, ErrAccessTokenExpired) {
		t.Fatalf("expired err = %v, want ErrAccessTokenExpired", err)
	}
	_, _ = pool.Exec(ctx, `UPDATE profiles.org_access_tokens SET expires_at=NULL WHERE id=$1::uuid`, tok.ID)

	// Revoke -> subsequent resolve is token_revoked; second revoke is a no-op.
	revoked, err := svc.RevokeOrgAccessToken(ctx, slug, tok.ID)
	if err != nil || !revoked {
		t.Fatalf("revoke = (%v,%v), want (true,nil)", revoked, err)
	}
	if _, _, err := svc.ResolveOrgAccessToken(ctx, keyID, secret); !errors.Is(err, ErrAccessTokenRevoked) {
		t.Fatalf("revoked err = %v, want ErrAccessTokenRevoked", err)
	}
	if again, _ := svc.RevokeOrgAccessToken(ctx, slug, tok.ID); again {
		t.Fatalf("second revoke returned true, want false")
	}

	// Past expiry at mint time is rejected.
	past := time.Now().Add(-time.Hour)
	if _, _, err := svc.MintOrgAccessToken(ctx, slug, "bad", nil, "", &past); err == nil {
		t.Fatalf("mint with past expiry should fail")
	}

	// Host max-TTL caps a no-expiry request.
	capped := NewService(Options{Issuer: "https://test", OrgAccessTokenMaxTTL: time.Hour}, Keyset{}).WithPostgres(pool)
	tok2, _, err := capped.MintOrgAccessToken(ctx, slug, "capped", nil, "", nil)
	if err != nil {
		t.Fatalf("mint capped: %v", err)
	}
	if tok2.ExpiresAt == nil {
		t.Fatalf("expected capped expiry, got nil")
	}
	if d := time.Until(*tok2.ExpiresAt); d <= 0 || d > time.Hour+time.Minute {
		t.Fatalf("capped expiry out of range: %v", d)
	}
}
