package authhttp

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/siws"
	"github.com/stretchr/testify/require"
)

// TestSIWSCacheSharesInstanceWithoutRedis proves that, on a single Service with
// no Redis configured, a challenge stored via the challenge path is later
// findable via the login path — i.e. Put and Consume hit the SAME in-memory
// cache instance (#196).
//
// The SIWS challenge handler (GenerateSIWSChallenge) obtains its cache from
// s.siwsCache() and Puts the pending challenge; the login handler
// (VerifySIWSAndLogin) obtains its cache from a SEPARATE s.siwsCache() call and
// Consumes the nonce. Before the fix, siwsCache() returned a fresh cache per
// call, so the login-path Consume never saw the challenge-path Put and Solana
// login/link failed with challenge-not-found. This test drives that exact
// two-call sequence without a database (the cache is in-memory).
func TestSIWSCacheSharesInstanceWithoutRedis(t *testing.T) {
	s := newTestService(t)
	require.Nil(t, s.rd, "test must run without Redis so the in-memory branch is exercised")

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
