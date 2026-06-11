package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type batchEntitlementsProvider struct {
	staticEntitlementsProvider
	batch      map[string][]string
	batchErr   error
	batchCalls int
}

func (p *batchEntitlementsProvider) ListEntitlementsBatch(ctx context.Context, userIDs []string) (map[string][]string, error) {
	p.batchCalls++
	return p.batch, p.batchErr
}

func TestEnrichEntitlements_BatchProviderOneCall(t *testing.T) {
	s, _ := newClaimTestService(t, "multi")
	p := &batchEntitlementsProvider{batch: map[string][]string{"u1": {"premium"}}}
	s.WithEntitlements(p)

	users := []AdminUser{{ID: "u1"}, {ID: "u2"}}
	s.enrichEntitlements(context.Background(), users)

	require.Equal(t, 1, p.batchCalls)
	require.Equal(t, []string{"premium"}, users[0].Entitlements)
	require.Empty(t, users[1].Entitlements) // absent from batch result = none
}

func TestEnrichEntitlements_BatchErrorDegradesToNone(t *testing.T) {
	s, _ := newClaimTestService(t, "multi")
	p := &batchEntitlementsProvider{batchErr: errors.New("billing unreachable")}
	s.WithEntitlements(p)

	users := []AdminUser{{ID: "u1"}}
	s.enrichEntitlements(context.Background(), users)
	require.Empty(t, users[0].Entitlements)
}

func TestEnrichEntitlements_SingleProviderFallback(t *testing.T) {
	s, _ := newClaimTestService(t, "multi")
	s.WithEntitlements(&staticEntitlementsProvider{names: []string{"premium"}})

	users := []AdminUser{{ID: "u1"}, {ID: "u2"}}
	s.enrichEntitlements(context.Background(), users)
	require.Equal(t, []string{"premium"}, users[0].Entitlements)
	require.Equal(t, []string{"premium"}, users[1].Entitlements)
}
