package authcore

import (
	"context"
	"testing"
)

// TestIssueAccessToken_OwnedClaimsWinOverExtra verifies a caller's extra map cannot
// override AuthKit-owned claims (sub/iss/aud/iat/exp/entitlements) — the owned
// values win — while non-owned custom claims still pass through. This closes the
// impersonation/forgery vector without rejecting callers.
func TestIssueAccessToken_OwnedClaimsWinOverExtra(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)
	ctx := context.Background()

	tok, _, err := svc.IssueAccessToken(ctx, "user-1", "", map[string]any{
		"sub":              "attacker",
		"iss":              "https://evil.example",
		"exp":              1,
		"custom_app_claim": "ok",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims := verifyAgainstServiceJWKS(t, svc, tok)

	if claims["sub"] != "user-1" {
		t.Fatalf("sub must remain the authenticated user, got %v", claims["sub"])
	}
	if claims["iss"] == "https://evil.example" {
		t.Fatalf("iss must not be overridable via extra, got %v", claims["iss"])
	}
	if expF, ok := claims["exp"].(float64); !ok || expF == 1 {
		t.Fatalf("exp must be the AuthKit-derived expiry, not the caller's value; got %v", claims["exp"])
	}
	if claims["custom_app_claim"] != "ok" {
		t.Fatalf("non-owned custom claim should pass through, got %v", claims["custom_app_claim"])
	}
}

// TestIssueAccessToken_NonOwnedExtraPassesThrough confirms the common in-tree usage
// (session id, provider) still rides on the token unchanged.
func TestIssueAccessToken_NonOwnedExtraPassesThrough(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)
	ctx := context.Background()

	tok, _, err := svc.IssueAccessToken(ctx, "user-1", "", map[string]any{"sid": "session-xyz", "provider": "google"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims := verifyAgainstServiceJWKS(t, svc, tok)
	if claims["sid"] != "session-xyz" || claims["provider"] != "google" {
		t.Fatalf("non-owned extra claims should pass through, got sid=%v provider=%v", claims["sid"], claims["provider"])
	}
}
