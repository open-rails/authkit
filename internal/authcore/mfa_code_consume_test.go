package authcore

import (
	"context"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/storage/memory"
	"github.com/stretchr/testify/require"
)

// #199 F2/plan015: a stored MFA login code must be single-use. The atomic
// get+del consume lets exactly one caller redeem the correct code, closing the
// Get-then-Del race where two concurrent requests could both authenticate on the
// same code.
func TestConsumeMFACode_AtomicSingleUse(t *testing.T) {
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithEphemeralStore(memorystore.NewKV(), EphemeralMemory))

	userID := "user-single-use"
	codeHash := sha256Hex("123456")
	require.NoError(t, svc.storeMFACode(ctx, userID, codeHash, "email", "a@b.co", time.Minute))

	ok, err := svc.consumeMFACode(ctx, userID, codeHash)
	require.NoError(t, err)
	require.True(t, ok, "first consume of the correct code must succeed")

	ok, err = svc.consumeMFACode(ctx, userID, codeHash)
	require.NoError(t, err)
	require.False(t, ok, "the code is single-use: a second consume of the same code must fail")
}

// A presented wrong code spends the pending entry (one attempt per issued code,
// bounding online brute force of the short numeric code); the later correct
// attempt then fails and the user must request a fresh code.
func TestConsumeMFACode_WrongGuessSpendsCode(t *testing.T) {
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithEphemeralStore(memorystore.NewKV(), EphemeralMemory))

	userID := "user-wrong-guess"
	require.NoError(t, svc.storeMFACode(ctx, userID, sha256Hex("123456"), "email", "a@b.co", time.Minute))

	ok, err := svc.consumeMFACode(ctx, userID, sha256Hex("000000"))
	require.NoError(t, err)
	require.False(t, ok, "a wrong code returns false")

	ok, err = svc.consumeMFACode(ctx, userID, sha256Hex("123456"))
	require.NoError(t, err)
	require.False(t, ok, "the wrong guess spent the pending code; the correct code now fails")
}

// The step-up code path shares the same atomic single-use guarantee.
func TestConsumeMFAStepUpCode_AtomicSingleUse(t *testing.T) {
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithEphemeralStore(memorystore.NewKV(), EphemeralMemory))

	userID, sessionID := "user-stepup", "sess-1"
	codeHash := sha256Hex("654321")
	require.NoError(t, svc.storeMFAStepUpCode(ctx, userID, sessionID, codeHash, "email", "a@b.co", time.Minute))

	ok, err := svc.consumeMFAStepUpCode(ctx, userID, sessionID, codeHash, "email")
	require.NoError(t, err)
	require.True(t, ok, "first step-up consume must succeed")

	ok, err = svc.consumeMFAStepUpCode(ctx, userID, sessionID, codeHash, "email")
	require.NoError(t, err)
	require.False(t, ok, "step-up code must be single-use")
}
