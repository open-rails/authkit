package authcore

import (
	"context"
	"testing"
)

// TestMintAccessToken_OwnedClaimsWinOverExtra verifies a caller's extra map cannot
// override AuthKit-owned claims (sub/iss/aud/iat/exp/entitlements) — the owned
// values win — while non-owned custom claims still pass through. This closes the
// impersonation/forgery vector without rejecting callers.
func TestMintAccessToken_OwnedClaimsWinOverExtra(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)
	ctx := context.Background()

	tok, _, err := svc.MintAccessToken(ctx, "user-1", map[string]any{
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

// TestMintAccessToken_NonOwnedExtraPassesThrough confirms the common in-tree usage
// (session id, provider) still rides on the token unchanged.
func TestMintAccessToken_NonOwnedExtraPassesThrough(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)
	ctx := context.Background()

	tok, _, err := svc.MintAccessToken(ctx, "user-1", map[string]any{"sid": "session-xyz", "provider": "google"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims := verifyAgainstServiceJWKS(t, svc, tok)
	if claims["sid"] != "session-xyz" || claims["provider"] != "google" {
		t.Fatalf("non-owned extra claims should pass through, got sid=%v provider=%v", claims["sid"], claims["provider"])
	}
}

// TestMintAccessToken_ReservedClaimsDroppedFromExtra is the AK2-AUTH-01 regression:
// a caller's extra map must never populate an authority/identity/assurance claim the
// verifier trusts (roles/permissions/email/email_verified/user_tier/assurance/...).
// These are signed by AuthKit from authenticated state or not at all; a host
// forwarding request-influenced data into extra must not be able to mint a
// validly-signed token with attacker-chosen authority. Legitimate protocol claims
// (sid/provider/2fa_enrollment) and arbitrary custom claims must still pass through.
func TestMintAccessToken_ReservedClaimsDroppedFromExtra(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)
	ctx := context.Background()

	tok, _, err := svc.MintAccessToken(ctx, "user-1", map[string]any{
		// Reserved — must be dropped:
		"roles":            []string{"admin", "superuser"},
		"permissions":      []string{"billing:*:*"},
		"global_roles":     []string{"platform_admin"},
		"org_roles":        []string{"owner"},
		"groups":           []string{"root"},
		"email":            "victim@corp.example",
		"email_verified":   true,
		"username":         "victim",
		"discord_username": "victim#1",
		"user_tier":        "enterprise",
		"plan":             "enterprise",
		"delegated_sub":    "someone-else",
		"attributes":       map[string]any{"is_admin": true},
		"documents":        map[string]string{"example.entitlements/v1": "sha256:forged"},
		"amr":              []string{"mfa"},
		"acr":              "phr",
		"auth_time":        1,
		"jti":              "forged-jti",
		"mfa_enrolled":     true,
		// Allowed — must pass through:
		"sid":              "session-xyz",
		"provider":         "google",
		"2fa_enrollment":   true,
		"custom_app_claim": "ok",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims := verifyAgainstServiceJWKS(t, svc, tok)

	reserved := []string{
		"roles", "permissions", "global_roles", "org_roles", "groups",
		"email", "email_verified", "username", "discord_username",
		"user_tier", "plan", "delegated_sub", "attributes", "documents",
		"amr", "acr", "auth_time", "jti", "mfa_enrolled",
	}
	for _, k := range reserved {
		if v, ok := claims[k]; ok {
			t.Errorf("AK2-AUTH-01: reserved claim %q must be dropped from extra, but the token carries %q=%v", k, k, v)
		}
	}

	// The deliberate protocol claims and arbitrary custom claims still ride.
	if claims["sid"] != "session-xyz" || claims["provider"] != "google" {
		t.Errorf("protocol claims sid/provider must pass through, got sid=%v provider=%v", claims["sid"], claims["provider"])
	}
	if claims["2fa_enrollment"] != true {
		t.Errorf("2fa_enrollment must pass through (used by Mint2FAEnrollmentToken), got %v", claims["2fa_enrollment"])
	}
	if claims["custom_app_claim"] != "ok" {
		t.Errorf("custom app claim must pass through, got %v", claims["custom_app_claim"])
	}
	// sub stays the authenticated user regardless.
	if claims["sub"] != "user-1" {
		t.Errorf("sub must remain the authenticated user, got %v", claims["sub"])
	}
}
