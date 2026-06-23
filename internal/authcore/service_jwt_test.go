package authcore

import (
	"context"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

func TestMintServiceJWTDefaultsToFifteenMinutes(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	token, claims, err := MintServiceJWT(context.Background(), signer, "https://auth.example", ServiceJWTMintOptions{
		Subject:     "service:hentai0-runtime",
		Audiences:   []string{"openrails"},
		Permissions: []string{"openrails:entitlements:read", "openrails:entitlements:read"},
		IssuedAt:    now,
	})
	if err != nil {
		t.Fatalf("MintServiceJWT: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}
	if claims.ExpiresAt.Sub(claims.IssuedAt) != DefaultServiceJWTLifetime {
		t.Fatalf("lifetime=%s, want %s", claims.ExpiresAt.Sub(claims.IssuedAt), DefaultServiceJWTLifetime)
	}
	if len(claims.Permissions) != 1 || claims.Permissions[0] != "openrails:entitlements:read" {
		t.Fatalf("permissions=%v", claims.Permissions)
	}

	parsed := jwt.MapClaims{}
	if _, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(token, parsed); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if parsed["token_use"] != ServiceJWTTokenUse {
		t.Fatalf("token_use=%v", parsed["token_use"])
	}
	if parsed["jti"] == "" {
		t.Fatal("missing jti")
	}
}

func TestMintServiceJWTCapsExcessiveLifetime(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	if err != nil {
		t.Fatal(err)
	}
	_, claims, err := MintServiceJWT(context.Background(), signer, "https://auth.example", ServiceJWTMintOptions{
		Subject:   "service:hentai0-runtime",
		Audiences: []string{"openrails"},
		Lifetime:  time.Hour,
	})
	if err != nil {
		t.Fatalf("MintServiceJWT: %v", err)
	}
	if claims.ExpiresAt.Sub(claims.IssuedAt) != DefaultServiceJWTLifetime {
		t.Fatalf("lifetime=%s, want cap %s", claims.ExpiresAt.Sub(claims.IssuedAt), DefaultServiceJWTLifetime)
	}
}
