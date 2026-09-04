package redisstore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/oidckit"
)

// Consume is single-use: a replayed OIDC/OAuth2 callback cannot reuse the state.
func TestStateCacheConsumeIsSingleUse(t *testing.T) {
	c := NewStateCache(testdb.ScratchRedis(t), "", 0)
	ctx := context.Background()

	if err := c.Put(ctx, "s1", oidckit.StateData{Provider: "google"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	sd, ok, err := c.Consume(ctx, "s1")
	if err != nil || !ok || sd.Provider != "google" {
		t.Fatalf("first consume: want (google,true,nil), got (%q,%v,%v)", sd.Provider, ok, err)
	}
	if _, ok, err := c.Consume(ctx, "s1"); ok || err != nil {
		t.Fatalf("second consume: got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	if _, ok, err := c.Get(ctx, "s1"); ok || err != nil {
		t.Fatalf("get after consume: got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}

func TestStateCacheConsumeConcurrentSingleWinner(t *testing.T) {
	c := NewStateCache(testdb.ScratchRedis(t), "", 0)
	ctx := context.Background()
	if err := c.Put(ctx, "s1", oidckit.StateData{Provider: "google"}); err != nil {
		t.Fatalf("put: %v", err)
	}

	const n = 32
	var wg sync.WaitGroup
	oks := make([]bool, n)
	start := make(chan struct{})
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			_, ok, _ := c.Consume(ctx, "s1")
			oks[i] = ok
		}(i)
	}
	close(start)
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

func TestStateCacheExpires(t *testing.T) {
	c := NewStateCache(testdb.ScratchRedis(t), "", 50*time.Millisecond)
	ctx := context.Background()
	if err := c.Put(ctx, "s1", oidckit.StateData{Provider: "google"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if _, ok, err := c.Consume(ctx, "s1"); ok || err != nil {
		t.Fatalf("consume after TTL: got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}
