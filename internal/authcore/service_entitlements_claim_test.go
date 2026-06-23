package authcore

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type staticEntitlementsProvider struct {
	names []string
	err   error
}

func (p *staticEntitlementsProvider) ListEntitlements(ctx context.Context, userID string) ([]string, error) {
	return p.names, p.err
}

// Provider names land verbatim in the `entitlements` claim.
func TestIssueAccessToken_EntitlementsClaim(t *testing.T) {
	s, pub := newClaimTestService(t, "multi", WithEntitlements(&staticEntitlementsProvider{names: []string{"premium"}}))

	tok, _, err := s.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err)
	cl := parseClaimsNoValidate(t, tok, pub)

	ents, ok := cl["entitlements"].([]any)
	require.True(t, ok, "entitlements claim must be present")
	require.Len(t, ents, 1)
	require.Equal(t, "premium", ents[0])
}

// Availability over consistency: a failing entitlements provider must not block
// token issuance — the token mints WITHOUT entitlement claims (and the failure
// is logged so operators can see users are not getting their entitlements).
func TestIssueAccessToken_EntitlementsProviderError_StillIssues(t *testing.T) {
	s, pub := newClaimTestService(t, "multi", WithEntitlements(&staticEntitlementsProvider{
		names: []string{"premium"}, // returned alongside the error; must be discarded
		err:   errors.New("billing unreachable"),
	}))

	tok, _, err := s.IssueAccessToken(context.Background(), "user", "e@example.com", map[string]any{})
	require.NoError(t, err, "provider failure must not block issuance")
	cl := parseClaimsNoValidate(t, tok, pub)

	ents, _ := cl["entitlements"].([]any)
	require.Empty(t, ents, "a token issued during a provider outage must carry no entitlement claims")
}
