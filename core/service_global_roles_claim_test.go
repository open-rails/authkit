package core

import (
	"context"
	"crypto/rsa"
	"testing"
	"time"

	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

func newClaimTestService(t *testing.T, orgMode string) (*Service, *rsa.PublicKey) {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	ks := Keyset{Active: signer, PublicKeys: map[string]*rsa.PublicKey{"kid": signer.PublicKey()}}
	s := NewService(Options{
		Issuer:              "https://example.com",
		IssuedAudiences:     []string{"app"},
		ExpectedAudiences:   []string{"app"},
		AccessTokenDuration: time.Hour,
		OrgMode:             orgMode,
	}, ks)
	return s, signer.PublicKey()
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

// Legacy `roles` behavior is unchanged: present in single, absent in multi
// (for a plain, non-org access token).
func TestIssueAccessToken_LegacyRolesClaim_Unchanged(t *testing.T) {
	sSingle, pubS := newClaimTestService(t, "single")
	tokS, _, err := sSingle.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)
	clS := parseClaimsNoValidate(t, tokS, pubS)
	_, ok := clS["roles"]
	require.True(t, ok, "legacy roles claim must be present in single mode")
	// plain access token (no org) carries no org_roles
	_, ok = clS["org_roles"]
	require.False(t, ok, "plain access token must not carry org_roles")

	sMulti, pubM := newClaimTestService(t, "multi")
	tokM, _, err := sMulti.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)
	clM := parseClaimsNoValidate(t, tokM, pubM)
	_, ok = clM["roles"]
	require.False(t, ok, "legacy roles claim must be absent in multi mode (plain token)")
}

// An org-scoped token (the claim shape IssueOrgAccessToken builds) carries
// global_roles AND org_roles, and keeps the legacy `roles` claim populated.
func TestIssueAccessToken_OrgScoped_CarriesGlobalAndOrgRoles(t *testing.T) {
	s, pub := newClaimTestService(t, "multi")
	// Mirror the extra map IssueOrgAccessToken assembles for an org-scoped token.
	extra := map[string]any{
		"org":       "acme",
		"roles":     []string{"editor"},
		"org_roles": []string{"editor"},
	}
	tok, _, err := s.IssueAccessToken(context.Background(), "user", "e@example.com", extra)
	require.NoError(t, err)
	cl := parseClaimsNoValidate(t, tok, pub)

	_, ok := cl["global_roles"]
	require.True(t, ok, "org-scoped token must carry global_roles")

	orgRoles, ok := cl["org_roles"].([]any)
	require.True(t, ok, "org-scoped token must carry org_roles")
	require.Len(t, orgRoles, 1)
	require.Equal(t, "editor", orgRoles[0])

	// legacy roles claim still populated for back-compat
	legacy, ok := cl["roles"].([]any)
	require.True(t, ok, "org-scoped token must keep legacy roles claim")
	require.Len(t, legacy, 1)
	require.Equal(t, "editor", legacy[0])
}
