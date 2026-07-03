package memorystore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit/oidckit"
)

// Consume is single-use: a second consume of the same state reports not-found, so
// a replayed OIDC/OAuth2 callback cannot reuse the pending state.
func TestStateCacheConsumeIsSingleUse(t *testing.T) {
	c := NewStateCache(time.Minute)
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()

	if err := c.Put(ctx, "s1", oidckit.StateData{Provider: "google"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	sd, ok, err := c.Consume(ctx, "s1")
	if err != nil || !ok || sd.Provider != "google" {
		t.Fatalf("first consume: want (google,true,nil), got (%q,%v,%v)", sd.Provider, ok, err)
	}
	if _, ok, _ := c.Consume(ctx, "s1"); ok {
		t.Fatal("second consume of the same state must miss")
	}
}

// Concurrent consumes of one state yield exactly one winner.
func TestStateCacheConsumeConcurrentSingleWinner(t *testing.T) {
	c := NewStateCache(time.Minute)
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()
	if err := c.Put(ctx, "s1", oidckit.StateData{Provider: "google"}); err != nil {
		t.Fatalf("put: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	oks := make([]bool, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, ok, _ := c.Consume(ctx, "s1")
			oks[i] = ok
		}(i)
	}
	wg.Wait()

	wins := 0
	for _, ok := range oks {
		if ok {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent consume: want exactly 1 winner, got %d", wins)
	}
}
