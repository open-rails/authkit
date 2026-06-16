package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestServiceTokenMarker(t *testing.T) {
	if got := ServiceTokenMarker(""); got != "st_" {
		t.Fatalf("empty prefix marker = %q, want %q", got, "st_")
	}
	if got := ServiceTokenMarker("cozy"); got != "cozy_st_" {
		t.Fatalf("branded marker = %q, want %q", got, "cozy_st_")
	}
	if got := ServiceTokenMarker("  cozy  "); got != "cozy_st_" {
		t.Fatalf("trimmed marker = %q, want %q", got, "cozy_st_")
	}
}

func TestFormatParseServiceTokenRoundTrip(t *testing.T) {
	cases := []struct{ prefix, keyID, secret string }{
		{"", "abc123KEYID00000", "SECRETvalue123base62"},
		{"cozy", "abc123KEYID00000", "SECRETvalue123base62"},
	}
	for _, tc := range cases {
		full := FormatServiceToken(tc.prefix, tc.keyID, tc.secret)
		if !HasServiceTokenPrefix(tc.prefix, full) {
			t.Fatalf("HasServiceTokenPrefix(%q, %q) = false", tc.prefix, full)
		}
		keyID, secret, ok := ParseServiceToken(tc.prefix, full)
		if !ok {
			t.Fatalf("ParseServiceToken(%q, %q) ok=false", tc.prefix, full)
		}
		if keyID != tc.keyID || secret != tc.secret {
			t.Fatalf("round-trip mismatch: got (%q,%q) want (%q,%q)", keyID, secret, tc.keyID, tc.secret)
		}
	}
}

func TestParseServiceTokenRejects(t *testing.T) {
	cases := []struct {
		name, prefix, token string
	}{
		{"no marker", "", "not-a-token"},
		{"jwt-looking", "cozy", "eyJhbGciOi.payload.sig"},
		{"wrong prefix", "cozy", "other_st_key_secret"},
		{"missing secret", "", "st_keyonly"},
		{"empty secret", "", "st_key_"},
		{"empty key", "", "st__secret"},
	}
	for _, tc := range cases {
		if _, _, ok := ParseServiceToken(tc.prefix, tc.token); ok {
			t.Errorf("%s: ParseServiceToken(%q,%q) ok=true, want false", tc.name, tc.prefix, tc.token)
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

func TestValidServiceTokenPrefix(t *testing.T) {
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
		if got := validServiceTokenPrefix(tc.prefix); got != tc.valid {
			t.Errorf("validServiceTokenPrefix(%q) = %v, want %v", tc.prefix, got, tc.valid)
		}
	}
}

func TestServiceTokenResourceContract(t *testing.T) {
	resources, err := normalizeServiceTokenResources([]ServiceTokenResource{
		{Kind: " openrails.merchant ", ID: " tensorhub "},
		{Kind: "openrails.customer", ID: "*"},
	})
	if err != nil {
		t.Fatalf("normalize resources: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("resources len=%d, want 2", len(resources))
	}
	if resources[0] != (ServiceTokenResource{Kind: "openrails.merchant", ID: "tensorhub"}) {
		t.Fatalf("trimmed resource = %+v", resources[0])
	}
	if resources[1].ID != "*" {
		t.Fatalf("wildcard-looking ID should be stored opaquely, got %+v", resources[1])
	}

	if _, err := normalizeServiceTokenResources([]ServiceTokenResource{{Kind: "org", ID: "x"}, {Kind: "org", ID: "x"}}); err == nil || err.Error() != "duplicate_resource" {
		t.Fatalf("duplicate err=%v, want duplicate_resource", err)
	}
	if _, err := normalizeServiceTokenResources([]ServiceTokenResource{{Kind: "", ID: "x"}}); err == nil || err.Error() != "invalid_resource" {
		t.Fatalf("empty kind err=%v, want invalid_resource", err)
	}
	if _, err := normalizeServiceTokenResources([]ServiceTokenResource{{Kind: "org", ID: strings.Repeat("x", serviceTokenResourceMaxLen+1)}}); err == nil || err.Error() != "invalid_resource" {
		t.Fatalf("long id err=%v, want invalid_resource", err)
	}
}

func TestResourceScopeAuthorizer(t *testing.T) {
	allowed := false
	svc := NewService(Options{
		Issuer: "https://test",
		ResourceScopeAuthorizer: func(ctx context.Context, req ResourceScopeAuthorizationRequest) error {
			if req.OrgSlug != "acme" || req.ActorUserID != "user-1" {
				t.Fatalf("unexpected request identity: %+v", req)
			}
			if len(req.Resources) != 1 || req.Resources[0] != (ServiceTokenResource{Kind: "repo", ID: "alpha"}) {
				t.Fatalf("unexpected resources: %+v", req.Resources)
			}
			allowed = true
			return nil
		},
	}, Keyset{})
	err := svc.AuthorizeServiceTokenResources(context.Background(), ResourceScopeAuthorizationRequest{
		OrgSlug:     " acme ",
		ActorUserID: " user-1 ",
		Resources:   []ServiceTokenResource{{Kind: " repo ", ID: " alpha "}},
	})
	if err != nil {
		t.Fatalf("authorize resources: %v", err)
	}
	if !allowed {
		t.Fatalf("authorizer was not called")
	}
}

// TestServiceTokenLifecycle exercises mint -> resolve -> list -> revoke ->
// rejected against a real database. Skips when AUTHKIT_TEST_DATABASE_URL is
// unset. created_by is left nil (audit-only, ON DELETE SET NULL) so the test
// needs no user fixture.
func TestServiceTokenLifecycle(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test", ServiceTokenPrefix: "cozy"}, Keyset{}).WithPostgres(pool)

	const slug = "service-token-lifecycle-test"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	var orgID string
	if err := pool.QueryRow(ctx, `INSERT INTO profiles.orgs (slug) VALUES ($1) RETURNING id::text`, slug).Scan(&orgID); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE id=$1::uuid`, orgID) })

	// Mint.
	resources := []ServiceTokenResource{
		{Kind: "openrails.merchant", ID: "tensorhub"},
		{Kind: "openrails.customer", ID: "cozy-art"},
	}
	tok, plaintext, err := svc.MintServiceTokenWithOptions(ctx, slug, ServiceTokenMintOptions{
		Name:        "ci-token",
		Permissions: []string{"deployer"},
		Resources:   resources,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !strings.HasPrefix(plaintext, "cozy_st_") {
		t.Fatalf("token %q lacks branded marker", plaintext)
	}
	keyID, secret, ok := ParseServiceToken("cozy", plaintext)
	if !ok || keyID != tok.KeyID {
		t.Fatalf("ParseServiceToken recovered (%q,ok=%v), want key %q", keyID, ok, tok.KeyID)
	}

	// Resolve success.
	gotOrg, gotScopes, err := svc.ResolveServiceToken(ctx, keyID, secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if gotOrg != slug {
		t.Fatalf("resolve org = %q, want %q", gotOrg, slug)
	}
	if len(gotScopes) != 1 || gotScopes[0] != "deployer" {
		t.Fatalf("resolve scopes = %v, want [deployer]", gotScopes)
	}
	resolved, err := svc.ResolveServiceTokenWithResources(ctx, keyID, secret)
	if err != nil {
		t.Fatalf("resolve with resources: %v", err)
	}
	if resolved.TokenID != tok.ID || resolved.KeyID != tok.KeyID || resolved.OrgSlug != slug {
		t.Fatalf("resolved metadata = %+v, token = %+v", resolved, tok)
	}
	if len(resolved.Resources) != 2 || resolved.Resources[0] != resources[0] || resolved.Resources[1] != resources[1] {
		t.Fatalf("resolved resources = %+v, want ordered by kind/id from %+v", resolved.Resources, resources)
	}

	// Wrong secret + unknown key_id are both invalid_token (no info leak).
	if _, _, err := svc.ResolveServiceToken(ctx, keyID, "wrongsecret"); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("wrong secret err = %v, want ErrInvalidAccessToken", err)
	}
	if _, _, err := svc.ResolveServiceToken(ctx, "nonexistentkey0", secret); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("unknown key err = %v, want ErrInvalidAccessToken", err)
	}

	// List returns metadata only (the struct has no secret field).
	list, err := svc.ListServiceTokens(ctx, slug)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].Name != "ci-token" || list[0].KeyID != tok.KeyID {
		t.Fatalf("list = %+v", list)
	}
	if len(list[0].Resources) != 2 {
		t.Fatalf("list resources = %+v, want 2 resources", list[0].Resources)
	}
	if _, _, err := svc.MintServiceTokenWithOptions(ctx, slug, ServiceTokenMintOptions{
		Name:      "dupe-resource",
		Resources: []ServiceTokenResource{{Kind: "repo", ID: "alpha"}, {Kind: "repo", ID: "alpha"}},
	}); err == nil || err.Error() != "duplicate_resource" {
		t.Fatalf("duplicate resource mint err=%v, want duplicate_resource", err)
	}

	// Expiry rejection (force past expiry).
	if _, err := pool.Exec(ctx, `UPDATE profiles.service_tokens SET expires_at=now()-interval '1 hour' WHERE id=$1::uuid`, tok.ID); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if _, _, err := svc.ResolveServiceToken(ctx, keyID, secret); !errors.Is(err, ErrAccessTokenExpired) {
		t.Fatalf("expired err = %v, want ErrAccessTokenExpired", err)
	}
	_, _ = pool.Exec(ctx, `UPDATE profiles.service_tokens SET expires_at=NULL WHERE id=$1::uuid`, tok.ID)

	// Revoke -> subsequent resolve is token_revoked; second revoke is a no-op.
	revoked, err := svc.RevokeServiceToken(ctx, slug, tok.ID)
	if err != nil || !revoked {
		t.Fatalf("revoke = (%v,%v), want (true,nil)", revoked, err)
	}
	if _, _, err := svc.ResolveServiceToken(ctx, keyID, secret); !errors.Is(err, ErrAccessTokenRevoked) {
		t.Fatalf("revoked err = %v, want ErrAccessTokenRevoked", err)
	}
	if again, _ := svc.RevokeServiceToken(ctx, slug, tok.ID); again {
		t.Fatalf("second revoke returned true, want false")
	}

	// Past expiry at mint time is rejected.
	past := time.Now().Add(-time.Hour)
	if _, _, err := svc.MintServiceToken(ctx, slug, "bad", nil, "", &past); err == nil {
		t.Fatalf("mint with past expiry should fail")
	}

	// Host max-TTL caps a no-expiry request.
	capped := NewService(Options{Issuer: "https://test", ServiceTokenMaxTTL: time.Hour}, Keyset{}).WithPostgres(pool)
	tok2, _, err := capped.MintServiceToken(ctx, slug, "capped", nil, "", nil)
	if err != nil {
		t.Fatalf("mint capped: %v", err)
	}
	if tok2.ExpiresAt == nil {
		t.Fatalf("expected capped expiry, got nil")
	}
	if d := time.Until(*tok2.ExpiresAt); d <= 0 || d > time.Hour+time.Minute {
		t.Fatalf("capped expiry out of range: %v", d)
	}

	legacyTok, legacyPlaintext, err := svc.MintServiceToken(ctx, slug, "legacy-wrapper", []string{"deployer"}, "", nil)
	if err != nil {
		t.Fatalf("mint legacy wrapper: %v", err)
	}
	legacyKeyID, legacySecret, ok := ParseServiceToken("cozy", legacyPlaintext)
	if !ok || legacyKeyID != legacyTok.KeyID {
		t.Fatalf("ParseServiceToken legacy recovered (%q,ok=%v), want key %q", legacyKeyID, ok, legacyTok.KeyID)
	}
	legacyResolved, err := svc.ResolveServiceTokenWithResources(ctx, legacyKeyID, legacySecret)
	if err != nil {
		t.Fatalf("resolve legacy wrapper with resources: %v", err)
	}
	if len(legacyResolved.Resources) != 0 {
		t.Fatalf("legacy resources = %+v, want empty", legacyResolved.Resources)
	}

	oneResourceTok, oneResourcePlaintext, err := svc.MintServiceTokenWithOptions(ctx, slug, ServiceTokenMintOptions{
		Name:      "one-resource",
		Resources: []ServiceTokenResource{{Kind: "openrails.merchant", ID: "tensorhub"}},
	})
	if err != nil {
		t.Fatalf("mint one resource: %v", err)
	}
	oneKeyID, oneSecret, ok := ParseServiceToken("cozy", oneResourcePlaintext)
	if !ok || oneKeyID != oneResourceTok.KeyID {
		t.Fatalf("ParseServiceToken one-resource recovered (%q,ok=%v), want key %q", oneKeyID, ok, oneResourceTok.KeyID)
	}
	oneResolved, err := svc.ResolveServiceTokenWithResources(ctx, oneKeyID, oneSecret)
	if err != nil {
		t.Fatalf("resolve one resource: %v", err)
	}
	if len(oneResolved.Resources) != 1 || oneResolved.Resources[0] != (ServiceTokenResource{Kind: "openrails.merchant", ID: "tensorhub"}) {
		t.Fatalf("one resource resolved = %+v", oneResolved.Resources)
	}
}
