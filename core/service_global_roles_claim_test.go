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

func newClaimTestService(t *testing.T, orgMode string) (*Service, crypto.PublicKey) {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	ks := Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"kid": signer.PublicKey()}}
	s := NewService(Options{
		Issuer:              "https://example.com",
		IssuedAudiences:     []string{"app"},
		ExpectedAudiences:   []string{"app"},
		AccessTokenDuration: time.Hour,
	}, ks)
	return s, signer.PublicKey()
}

func TestIssueAccessToken_TypHeader(t *testing.T) {
	s, _ := newClaimTestService(t, "multi")
	tok, _, err := s.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)

	header := parseHeaderNoValidate(t, tok)
	require.Equal(t, jwtkit.AccessTokenType, header["typ"])
}

// global_roles is emitted in BOTH single and multi-org mode (additive).
func TestIssueAccessToken_GlobalRolesClaim_BothModes(t *testing.T) {
	for _, mode := range []string{"single", "multi"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			s, pub := newClaimTestService(t, mode)
			tok, _, err := s.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
			require.NoError(t, err)
			cl := parseClaimsNoValidate(t, tok, pub)
			_, ok := cl["global_roles"]
			require.True(t, ok, "global_roles claim must be present in %s mode", mode)
		})
	}
}

// (issue 60) The legacy `roles` claim is emitted on a user access token
// (mirrors global_roles) as fixed token-shape compatibility, independent of
// org memberships. User access tokens carry no org_roles.
func TestIssueAccessToken_LegacyRolesClaim_AlwaysPresent(t *testing.T) {
	s, pub := newClaimTestService(t, "")
	tok, _, err := s.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)
	cl := parseClaimsNoValidate(t, tok, pub)
	_, ok := cl["roles"]
	require.True(t, ok, "legacy roles claim must be present on a user access token")
	_, ok = cl["global_roles"]
	require.True(t, ok, "global_roles claim must be present")
	_, ok = cl["org_roles"]
	require.False(t, ok, "user access token must not carry org_roles")
}
