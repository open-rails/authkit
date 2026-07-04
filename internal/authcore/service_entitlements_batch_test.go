package authcore

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type batchEntitlementsProvider struct {
	batch      map[string][]string
	batchErr   error
	batchCalls int
}

func (p *batchEntitlementsProvider) ListEntitlements(ctx context.Context, userIDs []string) (map[string][]string, error) {
	p.batchCalls++
	return p.batch, p.batchErr
}

func TestEnrichEntitlements_BatchProviderOneCall(t *testing.T) {
	p := &batchEntitlementsProvider{batch: map[string][]string{"u1": {"premium"}}}
	s, _ := newClaimTestService(t, "multi", WithEntitlements(p))

	users := []AdminUser{{ID: "u1"}, {ID: "u2"}}
	s.enrichEntitlements(context.Background(), users)

	require.Equal(t, 1, p.batchCalls)
	require.Equal(t, []string{"premium"}, users[0].Entitlements)
	require.Empty(t, users[1].Entitlements) // absent from batch result = none
}

func TestEnrichEntitlements_BatchErrorDegradesToNone(t *testing.T) {
	p := &batchEntitlementsProvider{batchErr: errors.New("billing unreachable")}
	s, _ := newClaimTestService(t, "multi", WithEntitlements(p))

	users := []AdminUser{{ID: "u1"}}
	s.enrichEntitlements(context.Background(), users)
	require.Empty(t, users[0].Entitlements)
}

func TestEnrichEntitlements_StaticProviderCoversAllUsers(t *testing.T) {
	// #221: the provider interface is batch-native; a static fake answers for
	// every requested id (the former single-provider fallback path is gone).
	s, _ := newClaimTestService(t, "multi", WithEntitlements(&staticEntitlementsProvider{names: []string{"premium"}}))

	users := []AdminUser{{ID: "u1"}, {ID: "u2"}}
	s.enrichEntitlements(context.Background(), users)
	require.Equal(t, []string{"premium"}, users[0].Entitlements)
	require.Equal(t, []string{"premium"}, users[1].Entitlements)
}
