package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAPIKeyMarker(t *testing.T) {
	if got := APIKeyMarker(""); got != "st_" {
		t.Fatalf("empty prefix marker = %q, want %q", got, "st_")
	}
	if got := APIKeyMarker("cozy"); got != "cozy_st_" {
		t.Fatalf("branded marker = %q, want %q", got, "cozy_st_")
	}
	if got := APIKeyMarker("  cozy  "); got != "cozy_st_" {
		t.Fatalf("trimmed marker = %q, want %q", got, "cozy_st_")
	}
}

func TestFormatParseAPIKeyRoundTrip(t *testing.T) {
	cases := []struct{ prefix, keyID, secret string }{
		{"", "abc123KEYID00000", "SECRETvalue123base62"},
		{"cozy", "abc123KEYID00000", "SECRETvalue123base62"},
	}
	for _, tc := range cases {
		full := FormatAPIKey(tc.prefix, tc.keyID, tc.secret)
		if !HasAPIKeyPrefix(tc.prefix, full) {
			t.Fatalf("HasAPIKeyPrefix(%q, %q) = false", tc.prefix, full)
		}
		keyID, secret, ok := ParseAPIKey(tc.prefix, full)
		if !ok {
			t.Fatalf("ParseAPIKey(%q, %q) ok=false", tc.prefix, full)
		}
		if keyID != tc.keyID || secret != tc.secret {
			t.Fatalf("round-trip mismatch: got (%q,%q) want (%q,%q)", keyID, secret, tc.keyID, tc.secret)
		}
	}
}

func TestParseAPIKeyRejects(t *testing.T) {
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
		if _, _, ok := ParseAPIKey(tc.prefix, tc.token); ok {
			t.Errorf("%s: ParseAPIKey(%q,%q) ok=true, want false", tc.name, tc.prefix, tc.token)
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

func TestValidAPIKeyPrefix(t *testing.T) {
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
		if got := validAPIKeyPrefix(tc.prefix); got != tc.valid {
			t.Errorf("validAPIKeyPrefix(%q) = %v, want %v", tc.prefix, got, tc.valid)
		}
	}
}

func TestAPIKeyPrefixAndTTLConfigured(t *testing.T) {
	svc := NewService(Options{Issuer: "https://test", APIKeyPrefix: "or", APIKeyMaxTTL: time.Hour}, Keyset{})
	opts := svc.Options()
	if opts.APIKeyPrefix != "or" {
		t.Fatalf("prefix not normalized: %+v", opts)
	}
	if opts.APIKeyMaxTTL != time.Hour {
		t.Fatalf("ttl not normalized: %+v", opts)
	}
}

func TestAPIKeyResourceContract(t *testing.T) {
	resources, err := normalizeAPIKeyResources([]APIKeyResource{
		{Kind: " openrails.merchant ", ID: " tensorhub "},
		{Kind: "openrails.customer", ID: "*"},
	})
	if err != nil {
		t.Fatalf("normalize resources: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("resources len=%d, want 2", len(resources))
	}
	if resources[0] != (APIKeyResource{Kind: "openrails.merchant", ID: "tensorhub"}) {
		t.Fatalf("trimmed resource = %+v", resources[0])
	}
	if resources[1].ID != "*" {
		t.Fatalf("wildcard-looking ID should be stored opaquely, got %+v", resources[1])
	}

	if _, err := normalizeAPIKeyResources([]APIKeyResource{{Kind: "org", ID: "x"}, {Kind: "org", ID: "x"}}); err == nil || err.Error() != "duplicate_resource" {
		t.Fatalf("duplicate err=%v, want duplicate_resource", err)
	}
	if _, err := normalizeAPIKeyResources([]APIKeyResource{{Kind: "", ID: "x"}}); err == nil || err.Error() != "invalid_resource" {
		t.Fatalf("empty kind err=%v, want invalid_resource", err)
	}
	if _, err := normalizeAPIKeyResources([]APIKeyResource{{Kind: "org", ID: strings.Repeat("x", apiKeyResourceMaxLen+1)}}); err == nil || err.Error() != "invalid_resource" {
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
			if len(req.Resources) != 1 || req.Resources[0] != (APIKeyResource{Kind: "repo", ID: "alpha"}) {
				t.Fatalf("unexpected resources: %+v", req.Resources)
			}
			allowed = true
			return nil
		},
	}, Keyset{})
	err := svc.AuthorizeAPIKeyResources(context.Background(), ResourceScopeAuthorizationRequest{
		OrgSlug:     " acme ",
		ActorUserID: " user-1 ",
		Resources:   []APIKeyResource{{Kind: " repo ", ID: " alpha "}},
	})
	if err != nil {
		t.Fatalf("authorize resources: %v", err)
	}
	if !allowed {
		t.Fatalf("authorizer was not called")
	}
}

// TestAPIKeyLifecycle exercises mint -> resolve -> list -> revoke ->
// rejected against a real database. Skips when AUTHKIT_TEST_DATABASE_URL is
// unset. created_by is left nil (audit-only, ON DELETE SET NULL) so the test
// needs no user fixture.
func TestAPIKeyLifecycle(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test", APIKeyPrefix: "cozy"}, Keyset{}).WithPostgres(pool)

	const slug = "service-key-lifecycle-test"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	var orgID string
	if err := pool.QueryRow(ctx, `INSERT INTO profiles.orgs (slug) VALUES ($1) RETURNING id::text`, slug).Scan(&orgID); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE id=$1::uuid`, orgID) })

	// Mint.
	resources := []APIKeyResource{
		{Kind: "openrails.merchant", ID: "tensorhub"},
		{Kind: "openrails.customer", ID: "cozy-art"},
	}
	tok, plaintext, err := svc.MintAPIKeyWithOptions(ctx, slug, APIKeyMintOptions{
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
	keyID, secret, ok := ParseAPIKey("cozy", plaintext)
	if !ok || keyID != tok.KeyID {
		t.Fatalf("ParseAPIKey recovered (%q,ok=%v), want key %q", keyID, ok, tok.KeyID)
	}

	// Resolve success.
	gotOrg, gotScopes, err := svc.ResolveAPIKey(ctx, keyID, secret)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if gotOrg != slug {
		t.Fatalf("resolve org = %q, want %q", gotOrg, slug)
	}
	if len(gotScopes) != 1 || gotScopes[0] != "deployer" {
		t.Fatalf("resolve scopes = %v, want [deployer]", gotScopes)
	}
	resolved, err := svc.ResolveAPIKeyWithResources(ctx, keyID, secret)
	if err != nil {
		t.Fatalf("resolve with resources: %v", err)
	}
	if resolved.APIKeyID != tok.ID || resolved.KeyID != tok.KeyID || resolved.OrgSlug != slug {
		t.Fatalf("resolved metadata = %+v, token = %+v", resolved, tok)
	}
	wantResources := []APIKeyResource{
		{Kind: "openrails.customer", ID: "cozy-art"},
		{Kind: "openrails.merchant", ID: "tensorhub"},
	}
	if len(resolved.Resources) != len(wantResources) || resolved.Resources[0] != wantResources[0] || resolved.Resources[1] != wantResources[1] {
		t.Fatalf("resolved resources = %+v, want ordered by kind/id %+v", resolved.Resources, wantResources)
	}

	// Wrong secret + unknown key_id are both invalid_token (no info leak).
	if _, _, err := svc.ResolveAPIKey(ctx, keyID, "wrongsecret"); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("wrong secret err = %v, want ErrInvalidAccessToken", err)
	}
	if _, _, err := svc.ResolveAPIKey(ctx, "nonexistentkey0", secret); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("unknown key err = %v, want ErrInvalidAccessToken", err)
	}

	// List returns metadata only (the struct has no secret field).
	list, err := svc.ListAPIKeys(ctx, slug)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].Name != "ci-token" || list[0].KeyID != tok.KeyID {
		t.Fatalf("list = %+v", list)
	}
	if len(list[0].Resources) != 2 {
		t.Fatalf("list resources = %+v, want 2 resources", list[0].Resources)
	}
	if _, _, err := svc.MintAPIKeyWithOptions(ctx, slug, APIKeyMintOptions{
		Name:      "dupe-resource",
		Resources: []APIKeyResource{{Kind: "repo", ID: "alpha"}, {Kind: "repo", ID: "alpha"}},
	}); err == nil || err.Error() != "duplicate_resource" {
		t.Fatalf("duplicate resource mint err=%v, want duplicate_resource", err)
	}

	// Expiry rejection (force past expiry).
	if _, err := pool.Exec(ctx, `UPDATE profiles.service_tokens SET expires_at=now()-interval '1 hour' WHERE id=$1::uuid`, tok.ID); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if _, _, err := svc.ResolveAPIKey(ctx, keyID, secret); !errors.Is(err, ErrAccessTokenExpired) {
		t.Fatalf("expired err = %v, want ErrAccessTokenExpired", err)
	}
	_, _ = pool.Exec(ctx, `UPDATE profiles.service_tokens SET expires_at=NULL WHERE id=$1::uuid`, tok.ID)

	// Revoke -> subsequent resolve is token_revoked; second revoke is a no-op.
	revoked, err := svc.RevokeAPIKey(ctx, slug, tok.ID)
	if err != nil || !revoked {
		t.Fatalf("revoke = (%v,%v), want (true,nil)", revoked, err)
	}
	if _, _, err := svc.ResolveAPIKey(ctx, keyID, secret); !errors.Is(err, ErrAccessTokenRevoked) {
		t.Fatalf("revoked err = %v, want ErrAccessTokenRevoked", err)
	}
	if again, _ := svc.RevokeAPIKey(ctx, slug, tok.ID); again {
		t.Fatalf("second revoke returned true, want false")
	}

	// Past expiry at mint time is rejected.
	past := time.Now().Add(-time.Hour)
	if _, _, err := svc.MintAPIKey(ctx, slug, "bad", nil, "", &past); err == nil {
		t.Fatalf("mint with past expiry should fail")
	}

	// Host max-TTL caps a no-expiry request.
	capped := NewService(Options{Issuer: "https://test", APIKeyMaxTTL: time.Hour}, Keyset{}).WithPostgres(pool)
	tok2, _, err := capped.MintAPIKey(ctx, slug, "capped", nil, "", nil)
	if err != nil {
		t.Fatalf("mint capped: %v", err)
	}
	if tok2.ExpiresAt == nil {
		t.Fatalf("expected capped expiry, got nil")
	}
	if d := time.Until(*tok2.ExpiresAt); d <= 0 || d > time.Hour+time.Minute {
		t.Fatalf("capped expiry out of range: %v", d)
	}

	legacyTok, legacyPlaintext, err := svc.MintAPIKey(ctx, slug, "legacy-wrapper", []string{"deployer"}, "", nil)
	if err != nil {
		t.Fatalf("mint legacy wrapper: %v", err)
	}
	legacyKeyID, legacySecret, ok := ParseAPIKey("cozy", legacyPlaintext)
	if !ok || legacyKeyID != legacyTok.KeyID {
		t.Fatalf("ParseAPIKey legacy recovered (%q,ok=%v), want key %q", legacyKeyID, ok, legacyTok.KeyID)
	}
	legacyResolved, err := svc.ResolveAPIKeyWithResources(ctx, legacyKeyID, legacySecret)
	if err != nil {
		t.Fatalf("resolve legacy wrapper with resources: %v", err)
	}
	if len(legacyResolved.Resources) != 0 {
		t.Fatalf("legacy resources = %+v, want empty", legacyResolved.Resources)
	}

	oneResourceTok, oneResourcePlaintext, err := svc.MintAPIKeyWithOptions(ctx, slug, APIKeyMintOptions{
		Name:      "one-resource",
		Resources: []APIKeyResource{{Kind: "openrails.merchant", ID: "tensorhub"}},
	})
	if err != nil {
		t.Fatalf("mint one resource: %v", err)
	}
	oneKeyID, oneSecret, ok := ParseAPIKey("cozy", oneResourcePlaintext)
	if !ok || oneKeyID != oneResourceTok.KeyID {
		t.Fatalf("ParseAPIKey one-resource recovered (%q,ok=%v), want key %q", oneKeyID, ok, oneResourceTok.KeyID)
	}
	oneResolved, err := svc.ResolveAPIKeyWithResources(ctx, oneKeyID, oneSecret)
	if err != nil {
		t.Fatalf("resolve one resource: %v", err)
	}
	if len(oneResolved.Resources) != 1 || oneResolved.Resources[0] != (APIKeyResource{Kind: "openrails.merchant", ID: "tensorhub"}) {
		t.Fatalf("one resource resolved = %+v", oneResolved.Resources)
	}
}
