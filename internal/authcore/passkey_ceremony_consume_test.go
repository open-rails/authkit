package authcore

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/storage/memory"
)

// TestConsumePasskeyCeremony_SingleUseUnderConcurrency is the AK2-PK-001 regression:
// a stored WebAuthn challenge must be consumable AT MOST ONCE even when many finish
// requests race on the same challenge. Before the fix (non-atomic Get+Del) multiple
// concurrent consumers could all observe the SessionData before any delete landed,
// enabling assertion/registration replay. With the atomic Consume primitive exactly
// one consumer may win. No DB needed — the ceremony lives only in the ephemeral store.
func TestConsumePasskeyCeremony_SingleUseUnderConcurrency(t *testing.T) {
	svc := NewService(Options{}, Keyset{}, WithEphemeralStore(memorystore.NewKV(), EphemeralMemory))
	ctx := context.Background()

	const (
		iterations = 300
		racers     = 64
	)
	for i := 0; i < iterations; i++ {
		challenge := fmt.Sprintf("challenge-%d", i)
		if err := svc.storePasskeyCeremony(ctx, challenge, passkeyCeremonyData{UserID: "u1", Session: []byte("sess")}, time.Minute); err != nil {
			t.Fatalf("store ceremony: %v", err)
		}

		var wins int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for r := 0; r < racers; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start // release all goroutines at once to maximize the race
				if _, err := svc.consumePasskeyCeremony(ctx, challenge); err == nil {
					atomic.AddInt64(&wins, 1)
				}
			}()
		}
		close(start)
		wg.Wait()

		if wins != 1 {
			t.Fatalf("iteration %d: challenge consumed %d times, want exactly 1 (replay window)", i, wins)
		}
	}
}

// TestEphemeralConsume_Semantics pins the primitive both in-tree stores must honor:
// Consume returns a value exactly once, then reports not-found.
func TestEphemeralConsume_Semantics(t *testing.T) {
	store := memorystore.NewKV()
	ctx := context.Background()

	if err := store.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	b, ok, err := store.Consume(ctx, "k")
	if err != nil || !ok || string(b) != "v" {
		t.Fatalf("first consume: got (%q, %v, %v), want (\"v\", true, nil)", b, ok, err)
	}
	// Second consume must miss — the key is gone.
	if _, ok, err := store.Consume(ctx, "k"); ok || err != nil {
		t.Fatalf("second consume: got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	// Missing key is a clean miss, not an error.
	if _, ok, err := store.Consume(ctx, "never"); ok || err != nil {
		t.Fatalf("missing consume: got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}
