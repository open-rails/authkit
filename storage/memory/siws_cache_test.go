package memorystore

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/siws"
)

// Consume is single-use: a second consume of the same nonce reports not-found,
// so a replayed SIWS signature cannot reuse the challenge.
func TestConsumeIsSingleUse(t *testing.T) {
	c := NewSIWSCache(time.Minute)
	ctx := context.Background()
	if err := c.Put(ctx, "nonce-1", siws.ChallengeData{Address: "addr", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("put: %v", err)
	}

	d, found, err := c.Consume(ctx, "nonce-1")
	if err != nil || !found {
		t.Fatalf("first consume: found=%v err=%v", found, err)
	}
	if d.Address != "addr" {
		t.Fatalf("address = %q, want addr", d.Address)
	}

	if _, found2, err := c.Consume(ctx, "nonce-1"); err != nil {
		t.Fatalf("second consume err: %v", err)
	} else if found2 {
		t.Fatal("nonce was consumable twice — SIWS replay window open")
	}
}

// Concurrent consumers of the same nonce: exactly one wins (single-winner), so
// the verify-then-act path can never run twice for one challenge.
func TestConsumeConcurrentSingleWinner(t *testing.T) {
	c := NewSIWSCache(time.Minute)
	ctx := context.Background()
	if err := c.Put(ctx, "n", siws.ChallengeData{Address: "a", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("put: %v", err)
	}

	const n = 50
	results := make(chan bool, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			<-start
			_, found, _ := c.Consume(ctx, "n")
			results <- found
		}()
	}
	close(start)

	wins := 0
	for i := 0; i < n; i++ {
		if <-results {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("expected exactly 1 winner consuming the nonce, got %d", wins)
	}
}

// A cache entry past its TTL is reported not-found by Consume (mirrors Get's
// expiry check). The cache expires by its own TTL clock, set at Put time — the
// challenge's own ExpiresAt is validated separately by the core layer.
func TestConsumeExpired(t *testing.T) {
	c := NewSIWSCache(20 * time.Millisecond)
	ctx := context.Background()
	if err := c.Put(ctx, "old", siws.ChallengeData{Address: "a"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	if _, found, err := c.Consume(ctx, "old"); err != nil || found {
		t.Fatalf("expired consume: found=%v err=%v (want found=false)", found, err)
	}
}
