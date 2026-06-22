package core

import (
	"context"
	"crypto"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

func parseClaimsNoValidate(t *testing.T, token string, pub crypto.PublicKey) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, err := parser.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) { return pub, nil })
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	return claims
}

func parseHeaderNoValidate(t *testing.T, token string) map[string]any {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	return parsed.Header
}

func newClaimTestService(t *testing.T, orgMode string, coreOpts ...Option) (*Service, crypto.PublicKey) {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	ks := Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"kid": signer.PublicKey()}}
	s := NewService(Options{
		Issuer:              "https://example.com",
		IssuedAudiences:     []string{"app"},
		ExpectedAudiences:   []string{"app"},
		AccessTokenDuration: time.Hour,
	}, ks, coreOpts...)
	return s, signer.PublicKey()
}

func TestIssueAccessToken_TypHeader(t *testing.T) {
	s, _ := newClaimTestService(t, "multi")
	tok, _, err := s.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)

	header := parseHeaderNoValidate(t, tok)
	require.Equal(t, jwtkit.AccessTokenType, header["typ"])
}

// The legacy global-roles plane was hard-cut: platform/org authority is resolved
// at request time from the platform/org RBAC tables, never snapshotted into the
// access token. Assert the dead claims are GONE so a regression that re-adds them
// fails here.
func TestIssueAccessToken_NoLegacyRoleClaims(t *testing.T) {
	for _, mode := range []string{"single", "multi", ""} {
		mode := mode
		t.Run("mode="+mode, func(t *testing.T) {
			s, pub := newClaimTestService(t, mode)
			tok, _, err := s.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
			require.NoError(t, err)
			cl := parseClaimsNoValidate(t, tok, pub)
			_, ok := cl["global_roles"]
			require.False(t, ok, "global_roles claim must be gone (hard-cut)")
			_, ok = cl["roles"]
			require.False(t, ok, "legacy roles claim must be gone (hard-cut)")
			_, ok = cl["org_roles"]
			require.False(t, ok, "user access token must not carry org_roles")
		})
	}
}

func TestIssueAccessToken_SlimUserClaimsKeepsSessionAndEntitlements(t *testing.T) {
	s, pub := newClaimTestService(t, "", WithEntitlements(&staticEntitlementsProvider{names: []string{"premium"}}))

	tok, _, err := s.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{
		"sid": "session-1",
	})
	require.NoError(t, err)

	cl := parseClaimsNoValidate(t, tok, pub)
	require.Equal(t, "user", cl["sub"])
	require.Equal(t, "session-1", cl["sid"])
	require.ElementsMatch(t, []any{"premium"}, cl["entitlements"])

	for _, forbidden := range []string{
		"email",
		"email_verified",
		"username",
		"discord_username",
		"roles",
		"global_roles",
		"org_roles",
	} {
		_, ok := cl[forbidden]
		require.False(t, ok, "%s claim must not be minted on normal user access tokens", forbidden)
	}
}
