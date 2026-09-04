package redisstore

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/siws"
	"github.com/open-rails/authkit/internal/testdb"
)

// Consume is single-use: a replayed SIWS signature cannot reuse the nonce.
func TestSIWSCacheConsumeIsSingleUse(t *testing.T) {
	c := NewSIWSCache(testdb.ScratchRedis(t), "", 0)
	ctx := context.Background()
	if err := c.Put(ctx, "nonce-1", siws.ChallengeData{Address: "addr", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("put: %v", err)
	}

	d, found, err := c.Consume(ctx, "nonce-1")
	if err != nil || !found || d.Address != "addr" {
		t.Fatalf("first consume: found=%v err=%v address=%q", found, err, d.Address)
	}
	if _, found, err := c.Consume(ctx, "nonce-1"); found || err != nil {
		t.Fatalf("second consume: got (found=%v, err=%v), want (false, nil) — SIWS replay window open", found, err)
	}
	if _, found, err := c.Get(ctx, "nonce-1"); found || err != nil {
		t.Fatalf("get after consume: got (found=%v, err=%v), want (false, nil)", found, err)
	}
}

func TestSIWSCacheConsumeConcurrentSingleWinner(t *testing.T) {
	c := NewSIWSCache(testdb.ScratchRedis(t), "", 0)
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

func TestSIWSCacheExpires(t *testing.T) {
	c := NewSIWSCache(testdb.ScratchRedis(t), "", 50*time.Millisecond)
	ctx := context.Background()
	if err := c.Put(ctx, "n", siws.ChallengeData{Address: "a", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("put: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if _, found, err := c.Consume(ctx, "n"); found || err != nil {
		t.Fatalf("consume after TTL: got (found=%v, err=%v), want (false, nil)", found, err)
	}
}
