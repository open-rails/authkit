package authcore

import (
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
		{Persona: " openrails.merchant ", ID: " tensorhub "},
		{Persona: "openrails.customer", ID: "*"},
	})
	if err != nil {
		t.Fatalf("normalize resources: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("resources len=%d, want 2", len(resources))
	}
	if resources[0] != (APIKeyResource{Persona: "openrails.merchant", ID: "tensorhub"}) {
		t.Fatalf("trimmed resource = %+v", resources[0])
	}
	if resources[1].ID != "*" {
		t.Fatalf("wildcard-looking ID should be stored opaquely, got %+v", resources[1])
	}

	if _, err := normalizeAPIKeyResources([]APIKeyResource{{Persona: "merchant", ID: "x"}, {Persona: "merchant", ID: "x"}}); err == nil || err.Error() != "duplicate_resource" {
		t.Fatalf("duplicate err=%v, want duplicate_resource", err)
	}
	if _, err := normalizeAPIKeyResources([]APIKeyResource{{Persona: "", ID: "x"}}); err == nil || err.Error() != "invalid_resource" {
		t.Fatalf("empty kind err=%v, want invalid_resource", err)
	}
	if _, err := normalizeAPIKeyResources([]APIKeyResource{{Persona: "merchant", ID: strings.Repeat("x", apiKeyResourceMaxLen+1)}}); err == nil || err.Error() != "invalid_resource" {
		t.Fatalf("long id err=%v, want invalid_resource", err)
	}
}
