package embedded

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

type tokenEntitlementFixture struct {
	calls  int
	grants []string
	err    error
}

func (p *tokenEntitlementFixture) ListEntitlements(_ context.Context, users []string) (map[string][]string, error) {
	p.calls++
	return map[string][]string{users[0]: p.grants}, p.err
}

func TestTokenEntitlementSelectionAndBounds(t *testing.T) {
	input := []string{"premium", "lifetime", "premium"}
	names, err := normalizeEntitlementAllowlist(input)
	require.NoError(t, err)
	require.Equal(t, []string{"lifetime", "premium"}, names)
	input[0] = "changed"
	require.Equal(t, []string{"lifetime", "premium"}, names)
	for _, bad := range [][]string{{""}, {" premium"}, {strings.Repeat("x", 129)}, {string([]byte{0xff})}} {
		_, err := normalizeConfig(Config{Token: TokenConfig{EntitlementAllowlist: bad}})
		require.Error(t, err)
	}
	tooMany := make([]string, 33)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("feature-%d", i)
	}
	_, err = normalizeEntitlementAllowlist(tooMany)
	require.Error(t, err)
	tooLarge := make([]string, 32)
	for i := range tooLarge {
		tooLarge[i] = fmt.Sprintf("%02d", i) + strings.Repeat("x", 126)
	}
	_, err = normalizeEntitlementAllowlist(tooLarge)
	require.Error(t, err)
	provider := &tokenEntitlementFixture{grants: []string{"premium", "product-1", "premium", "unselected"}}
	signer, err := jwtkit.NewRSASigner(2048, "entitlements")
	require.NoError(t, err)
	keys := Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}
	newEngineFor := func(allowlist []string) *engine {
		t.Helper()
		return mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://entitlements.test", IssuedAudiences: []string{"app"}, EntitlementAllowlist: allowlist}, Ephemeral: EphemeralConfig{AllowMemory: true}}, keys, Deps{Entitlements: provider})
	}
	v := verify.NewVerifier()
	require.NoError(t, v.AddIssuer("https://entitlements.test", []string{"app"}, verify.IssuerOptions{IsLocal: true, RawKeys: keys.PublicKeys}))
	mint := func(s *engine) map[string]any {
		t.Helper()
		token, _, err := s.MintAccessToken(t.Context(), "user", map[string]any{"entitlements": []string{"forged"}, "root_permissions": map[string]any{"grants": []string{"root:*"}}, "roles": []string{"owner"}, "permissions": []string{"root:*"}})
		require.NoError(t, err)
		claims, err := v.VerifyClaims(t.Context(), token)
		require.NoError(t, err)
		require.NotContains(t, claims, "root_permissions")
		require.NotContains(t, claims, "roles")
		require.NotContains(t, claims, "permissions")
		return claims
	}
	claims := mint(newEngineFor(nil))
	require.NotContains(t, claims, "entitlements")
	require.Zero(t, provider.calls)
	s := newEngineFor([]string{"premium", "lifetime"})
	claims = mint(s)
	require.Equal(t, []any{"premium"}, claims["entitlements"])
	require.Equal(t, provider.grants, s.ListEntitlements(t.Context(), "user"), "admin/directory responses remain unfiltered")
	provider.grants = []string{"product-1"}
	require.NotContains(t, mint(s), "entitlements", "an allowlist never manufactures a grant")
	provider.err = errors.New("provider unavailable")
	require.NotContains(t, mint(s), "entitlements", "provider failure must not prevent login or grant claims")
}
