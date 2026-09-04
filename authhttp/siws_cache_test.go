package authhttp

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/siws"
	"github.com/stretchr/testify/require"
)

// TestSIWSCacheConsumeIsSingleUse drives the two-call sequence the Solana flow
// uses: the challenge handler Puts via one s.siwsCache() call, the login handler
// Consumes via a SEPARATE call. Both must hit the same store (#196: the memory
// cache used to be rebuilt per call) and a consumed nonce must not verify again,
// on the memory store and on Redis alike.
func TestSIWSCacheConsumeIsSingleUse(t *testing.T) {
	forEachStore(t, testSIWSCacheConsumeIsSingleUse)
}

func testSIWSCacheConsumeIsSingleUse(t *testing.T, store ephemeralStore) {
	s := store.attach(newTestService(t))

	ctx := context.Background()
	const nonce = "test-nonce-196"
	want := siws.ChallengeData{
		Address:   "SoLwallet1111111111111111111111111111111111",
		Username:  "alice",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}

	// Challenge path: store the pending challenge.
	require.NoError(t, s.siwsCache().Put(ctx, nonce, want))

	// Login path: a SEPARATE siwsCache() call must find and consume it.
	got, ok, err := s.siwsCache().Consume(ctx, nonce)
	require.NoError(t, err)
	require.True(t, ok, "Consume must find the challenge stored by the challenge path (same cache instance)")
	require.Equal(t, want.Address, got.Address)
	require.Equal(t, want.Username, got.Username)

	// Consume is single-use: a second login attempt with the same nonce fails.
	_, ok, err = s.siwsCache().Consume(ctx, nonce)
	require.NoError(t, err)
	require.False(t, ok, "a consumed nonce must not verify again (replay protection)")
}
