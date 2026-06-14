package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// parseUnverified parses tok against the Service JWKS and returns the *jwt.Token
// so tests can inspect JOSE headers (e.g. `typ`).
func parseUnverified(t *testing.T, svc *Service, tok string) *jwt.Token {
	t.Helper()
	parsed, err := jwt.NewParser(jwt.WithoutClaimsValidation()).Parse(tok, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		pub, ok := svc.keys.PublicKeys[kid]
		if !ok {
			t.Fatalf("kid %q not on JWKS", kid)
		}
		return pub, nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return parsed
}

// TestMintCustomJWTRoundTrip mints a tensorhub-style capability token through the
// Service and verifies its custom claims (cap_kind, grants, release_id) and `typ`
// header survive a mint->parse round-trip against the Service JWKS.
func TestMintCustomJWTRoundTrip(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)

	tok, err := svc.MintCustomJWT(context.Background(), CustomJWTMintOptions{
		Type: "worker-capability+jwt",
		TTL:  10 * time.Minute,
		Claims: map[string]any{
			"cap_kind":   "worker",
			"grants":     []string{"job:run", "job:report"},
			"release_id": "rel-2026-06-13",
			"org":        "cozy-art",
		},
		Subject:   "service:tensorhub",
		Audiences: []string{"cozy.scheduler"},
	})
	if err != nil {
		t.Fatalf("MintCustomJWT: %v", err)
	}

	claims := verifyAgainstServiceJWKS(t, svc, tok)
	if claims["cap_kind"] != "worker" {
		t.Fatalf("cap_kind=%v", claims["cap_kind"])
	}
	if claims["release_id"] != "rel-2026-06-13" {
		t.Fatalf("release_id=%v", claims["release_id"])
	}
	if claims["org"] != "cozy-art" {
		t.Fatalf("org=%v", claims["org"])
	}
	grants, ok := claims["grants"].([]any)
	if !ok || len(grants) != 2 || grants[0] != "job:run" {
		t.Fatalf("grants=%v", claims["grants"])
	}
	if claims["sub"] != "service:tensorhub" {
		t.Fatalf("sub=%v", claims["sub"])
	}
	aud, ok := claims["aud"].([]any)
	if !ok || len(aud) != 1 || aud[0] != "cozy.scheduler" {
		t.Fatalf("aud=%v", claims["aud"])
	}
}

// TestMintCustomJWTTypeHeaderHonored proves the `typ` JOSE header reflects opts.Type.
func TestMintCustomJWTTypeHeaderHonored(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)

	tok, err := svc.MintCustomJWT(context.Background(), CustomJWTMintOptions{
		Type:   "my-custom+jwt",
		TTL:    time.Minute,
		Claims: map[string]any{"x": "y"},
	})
	if err != nil {
		t.Fatalf("MintCustomJWT: %v", err)
	}
	tokParsed := parseUnverified(t, svc, tok)
	if got := tokParsed.Header["typ"]; got != "my-custom+jwt" {
		t.Fatalf("typ header=%v", got)
	}
}

// TestMintCustomJWTIssuerDefaultAndOverride checks `iss` defaults to the Service
// issuer and can be overridden via the explicit Issuer option.
func TestMintCustomJWTIssuerDefaultAndOverride(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)

	def, err := svc.MintCustomJWT(context.Background(), CustomJWTMintOptions{
		TTL:    time.Minute,
		Claims: map[string]any{"x": "y"},
	})
	if err != nil {
		t.Fatalf("MintCustomJWT default: %v", err)
	}
	if claims := verifyAgainstServiceJWKS(t, svc, def); claims["iss"] != "https://issuer.test" {
		t.Fatalf("iss default=%v", claims["iss"])
	}

	over, err := svc.MintCustomJWT(context.Background(), CustomJWTMintOptions{
		TTL:    time.Minute,
		Issuer: "https://other.test",
		Claims: map[string]any{"x": "y"},
	})
	if err != nil {
		t.Fatalf("MintCustomJWT override: %v", err)
	}
	if claims := verifyAgainstServiceJWKS(t, svc, over); claims["iss"] != "https://other.test" {
		t.Fatalf("iss override=%v", claims["iss"])
	}
}

// TestMintCustomJWTTTLBound caps the lifetime at MaxCustomJWTLifetime even when
// the caller requests more.
func TestMintCustomJWTTTLBound(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)

	tok, err := svc.MintCustomJWT(context.Background(), CustomJWTMintOptions{
		TTL:    100 * time.Hour,
		Claims: map[string]any{"x": "y"},
	})
	if err != nil {
		t.Fatalf("MintCustomJWT: %v", err)
	}
	claims := verifyAgainstServiceJWKS(t, svc, tok)
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if span := time.Duration(exp-iat) * time.Second; span > MaxCustomJWTLifetime {
		t.Fatalf("ttl not bounded: span=%s", span)
	}
}

// TestMintCustomJWTReservedClaimRejected proves the host Claims map cannot clobber
// the AuthKit-owned registered claims iss/iat/exp.
func TestMintCustomJWTReservedClaimRejected(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)

	for _, reserved := range []string{"iss", "iat", "exp"} {
		_, err := svc.MintCustomJWT(context.Background(), CustomJWTMintOptions{
			TTL:    time.Minute,
			Claims: map[string]any{reserved: "nope", "x": "y"},
		})
		if !errors.Is(err, ErrCustomClaimsReserved) {
			t.Fatalf("claim %q: want ErrCustomClaimsReserved, got %v", reserved, err)
		}
	}
}

// TestMintCustomJWTGuardrails covers empty/oversized claim sets and missing TTL.
func TestMintCustomJWTGuardrails(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)
	ctx := context.Background()

	if _, err := svc.MintCustomJWT(ctx, CustomJWTMintOptions{TTL: time.Minute}); !errors.Is(err, ErrEmptyCustomClaims) {
		t.Fatalf("empty claims: want ErrEmptyCustomClaims, got %v", err)
	}

	big := make(map[string]any, maxCustomJWTClaims+1)
	for i := 0; i <= maxCustomJWTClaims; i++ {
		big[fmt.Sprintf("claim_%d", i)] = i
	}
	if _, err := svc.MintCustomJWT(ctx, CustomJWTMintOptions{TTL: time.Minute, Claims: big}); !errors.Is(err, ErrTooManyCustomClaims) {
		t.Fatalf("oversized claims: want ErrTooManyCustomClaims, got %v", err)
	}

	if _, err := svc.MintCustomJWT(ctx, CustomJWTMintOptions{Claims: map[string]any{"x": "y"}}); err == nil {
		t.Fatal("missing TTL: want error, got nil")
	}
}
