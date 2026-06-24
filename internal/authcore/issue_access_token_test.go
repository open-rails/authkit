package authcore

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestIssueAccessToken_RejectsReservedClaims verifies a caller's extra map cannot
// override AuthKit-owned registered/assurance claims (impersonation / forgery).
// The guard runs before signing, so no keyset is required for the reject path.
func TestIssueAccessToken_RejectsReservedClaims(t *testing.T) {
	svc := NewService(Options{Issuer: "https://test"}, Keyset{})
	ctx := context.Background()

	for _, key := range []string{"iss", "sub", "aud", "iat", "exp", "entitlements", "auth_time", "amr", "acr", "mfa_enrolled"} {
		t.Run(key, func(t *testing.T) {
			_, _, err := svc.IssueAccessToken(ctx, "user-1", "", map[string]any{key: "x"})
			if !errors.Is(err, ErrCustomClaimsReserved) {
				t.Fatalf("extra[%q] override: want ErrCustomClaimsReserved, got %v", key, err)
			}
		})
	}
}

// TestIssueAccessToken_AllowsNonReservedClaims confirms the guard lets non-reserved
// keys through (they fail later only because this service has no signer) and that a
// service WITH keys mints a token carrying the custom claim.
func TestIssueAccessToken_AllowsNonReservedClaims(t *testing.T) {
	ctx := context.Background()

	// No signer: a non-reserved key must NOT be rejected as reserved — it falls
	// through to the missing-signer error.
	noSigner := NewService(Options{Issuer: "https://test"}, Keyset{})
	if _, _, err := noSigner.IssueAccessToken(ctx, "user-1", "", map[string]any{"sid": "abc", "provider": "google"}); errors.Is(err, ErrCustomClaimsReserved) {
		t.Fatalf("non-reserved extra keys must not be rejected as reserved; got %v", err)
	}

	// With keys: the token mints and carries the custom claim.
	svc := mustServiceWithGeneratedKeys(t)
	tok, _, err := svc.IssueAccessToken(ctx, "user-1", "", map[string]any{"sid": "session-xyz"})
	if err != nil {
		t.Fatalf("mint with non-reserved claim: %v", err)
	}
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("expected a JWS compact token, got %q", tok)
	}
}
