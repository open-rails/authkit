package authhttp

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

type nativeEntitlementProvider struct {
	mu    sync.Mutex
	names []string
	fail  bool
	calls int
}

func (p *nativeEntitlementProvider) ListEntitlements(_ context.Context, users []string) (map[string][]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.fail {
		return nil, errors.New("test billing unavailable")
	}
	return map[string][]string{users[0]: append([]string(nil), p.names...)}, nil
}

func TestNativeEntitlementAllowlistRegistrationLoginRefresh(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	provider := &nativeEntitlementProvider{names: []string{"premium", "unselected", "product-a", "premium"}}
	newFlow := func(allowlist []string) *accountFlow {
		t.Helper()
		cfg := newServerTestConfig()
		cfg.Token.EntitlementAllowlist = allowlist
		cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
		core := newServerClient(t, cfg, pg.Pool, func(deps *embedded.Deps) { deps.Entitlements = provider })
		t.Cleanup(core.Close)
		srv, err := newTestService(core, workflowHTTPConfig())
		require.NoError(t, err)
		t.Cleanup(srv.Close)
		flow := &accountFlow{t: t, service: srv}
		flow.mount()
		t.Cleanup(flow.server.Close)
		return flow
	}
	f := newFlow(nil)
	registered := f.expect(http.StatusAccepted, f.post("/register", map[string]any{"identifier": "entitlement-policy@example.test", "username": "entpolicy", "password": "Correct-horse-policy-password-1"}))
	claims, err := f.service.Verifier().VerifyClaims(t.Context(), registered.Tokens.AccessToken)
	require.NoError(t, err)
	require.NotContains(t, claims, "entitlements")
	provider.mu.Lock()
	calls := provider.calls
	provider.mu.Unlock()
	require.Zero(t, calls, "empty allowlist must not query billing during registration")
	f = newFlow([]string{"premium", "lifetime"})
	login := f.expect(http.StatusOK, f.post("/password/login", map[string]any{"identifier": "entitlement-policy@example.test", "password": "Correct-horse-policy-password-1"}))
	claims, err = f.service.Verifier().VerifyClaims(t.Context(), login.AccessToken)
	require.NoError(t, err)
	require.Equal(t, []any{"premium"}, claims["entitlements"])
	for _, key := range []string{"roles", "permissions", "groups", "root_permissions"} {
		require.NotContains(t, claims, key)
	}
	assertWireGolden(t, "access-claims", claims)
	provider.mu.Lock()
	provider.names = []string{"lifetime", "product-b"}
	provider.mu.Unlock()
	refreshed := f.expect(http.StatusOK, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": login.RefreshToken}))
	claims, err = f.service.Verifier().VerifyClaims(t.Context(), refreshed.AccessToken)
	require.NoError(t, err)
	require.Equal(t, []any{"lifetime"}, claims["entitlements"])
	provider.mu.Lock()
	provider.fail = true
	provider.mu.Unlock()
	failed := f.expect(http.StatusOK, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": refreshed.RefreshToken}))
	claims, err = f.service.Verifier().VerifyClaims(t.Context(), failed.AccessToken)
	require.NoError(t, err)
	require.NotContains(t, claims, "entitlements", "provider failure does not become a grant or prevent login")
}
