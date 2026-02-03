package core

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

func parseClaimsNoValidate(t *testing.T, token string, pub *rsa.PublicKey) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, err := parser.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) { return pub, nil })
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	return claims
}

func TestIssueAccessToken_RolesClaim_SingleModeOnly(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	ks := Keyset{Active: signer, PublicKeys: map[string]*rsa.PublicKey{"kid": signer.PublicKey()}}

	// single: roles claim present (may be empty)
	sSingle := NewService(Options{
		Issuer:              "https://example.com",
		IssuedAudiences:     []string{"app"},
		ExpectedAudiences:   []string{"app"},
		AccessTokenDuration: time.Hour,
		OrgMode:             "single",
	}, ks)
	tokSingle, _, err := sSingle.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)
	cl1 := parseClaimsNoValidate(t, tokSingle, signer.PublicKey())
	_, ok := cl1["roles"]
	require.True(t, ok)

	// multi: roles claim omitted
	sMulti := NewService(Options{
		Issuer:              "https://example.com",
		IssuedAudiences:     []string{"app"},
		ExpectedAudiences:   []string{"app"},
		AccessTokenDuration: time.Hour,
		OrgMode:             "multi",
	}, ks)
	tokMulti, _, err := sMulti.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)
	cl2 := parseClaimsNoValidate(t, tokMulti, signer.PublicKey())
	_, ok = cl2["roles"]
	require.False(t, ok)
}
