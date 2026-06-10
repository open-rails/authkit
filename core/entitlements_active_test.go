package core

import (
	"testing"
	"time"

	entpg "github.com/open-rails/authkit/entitlements"
	"github.com/stretchr/testify/require"
)

func ptr(t time.Time) *time.Time { return &t }

func TestActiveEntitlementNames_ExcludesRevokedAndExpired(t *testing.T) {
	now := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	details := []entpg.Entitlement{
		{Name: "premium"},
		{Name: "revoked-now", RevokedAt: ptr(now)},
		{Name: "revoked-past", RevokedAt: ptr(now.Add(-time.Hour))},
		{Name: "expired", ExpiresAt: ptr(now.Add(-time.Minute))},
		{Name: "expires-now", ExpiresAt: ptr(now)},
		{Name: "future-revoke", RevokedAt: ptr(now.Add(time.Hour))},
		{Name: "future-expiry", ExpiresAt: ptr(now.Add(time.Hour))},
	}

	got := activeEntitlementNames(details, now)
	require.Equal(t, []string{"premium", "future-revoke", "future-expiry"}, got)
}

func TestActiveEntitlementNames_TrimsDedupsAndSkipsEmpty(t *testing.T) {
	now := time.Now().UTC()
	details := []entpg.Entitlement{
		{Name: "  premium  "},
		{Name: "Premium"},
		{Name: "PREMIUM"},
		{Name: "   "},
		{Name: ""},
		{Name: "pro"},
	}

	got := activeEntitlementNames(details, now)
	require.Equal(t, []string{"premium", "pro"}, got)
}

func TestActiveEntitlementNames_EmptyIsNonNil(t *testing.T) {
	got := activeEntitlementNames(nil, time.Now().UTC())
	require.NotNil(t, got)
	require.Empty(t, got)
}

func TestActiveEntitlements_PreservesMetadataForActiveOnly(t *testing.T) {
	now := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	details := []entpg.Entitlement{
		{Name: "premium", Source: "billing", Metadata: map[string]interface{}{"tier": "gold"}},
		{Name: "revoked", RevokedAt: ptr(now.Add(-time.Hour))},
	}

	got := activeEntitlements(details, now)
	require.Len(t, got, 1)
	require.Equal(t, "premium", got[0].Name)
	require.Equal(t, "billing", got[0].Source)
	require.Equal(t, "gold", got[0].Metadata["tier"])
}
