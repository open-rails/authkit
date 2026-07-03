package authcore

import (
	"context"
	"crypto"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/jwtkit"
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
	s := NewService(Config{Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}, ExpectedAudiences: []string{"app"}, AccessTokenDuration: time.Hour}}, ks, coreOpts...)
	return s, signer.PublicKey()
}

func TestIssueAccessToken_TypHeader(t *testing.T) {
	s, _ := newClaimTestService(t, "multi")
	tok, _, err := s.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)

	header := parseHeaderNoValidate(t, tok)
	require.Equal(t, jwtkit.AccessTokenType, header["typ"])
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
	} {
		_, ok := cl[forbidden]
		require.False(t, ok, "%s claim must not be minted on normal user access tokens", forbidden)
	}
}

// #112: the sanctioned post-construction SetEntitlementsProvider seam (used to
// break the embedded-billing init cycle) must be honored at mint time — a
// provider installed AFTER construction enriches the access token exactly as the
// WithEntitlements construction option would.
func TestSetEntitlementsProvider_LateBoundProviderEnrichesToken(t *testing.T) {
	s, pub := newClaimTestService(t, "") // built WITHOUT entitlements

	// No provider yet => no (or empty) entitlements.
	tok0, _, err := s.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{"sid": "s0"})
	require.NoError(t, err)
	cl0 := parseClaimsNoValidate(t, tok0, pub)
	require.Empty(t, cl0["entitlements"], "no entitlements before a provider is installed")

	// Install the provider after construction (the cyclic-dependency seam).
	s.SetEntitlementsProvider(&staticEntitlementsProvider{names: []string{"premium"}})

	tok1, _, err := s.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{"sid": "s1"})
	require.NoError(t, err)
	cl1 := parseClaimsNoValidate(t, tok1, pub)
	require.ElementsMatch(t, []any{"premium"}, cl1["entitlements"])
}
