package redisstore

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
)

// Consume must deliver a value to exactly ONE of many racing callers: the
// GETDEL primitive is what makes passkey challenges and reset tokens single-use.
func TestKVConsumeSingleWinnerUnderConcurrency(t *testing.T) {
	kv := NewKV(testdb.ScratchRedis(t), "t:")
	ctx := context.Background()
	const iterations, racers = 20, 64

	for i := 0; i < iterations; i++ {
		key := fmt.Sprintf("challenge-%d", i)
		if err := kv.Set(ctx, key, []byte("sess"), time.Minute); err != nil {
			t.Fatalf("set: %v", err)
		}
		var wins, errs int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for r := 0; r < racers; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, ok, err := kv.Consume(ctx, key)
				if err != nil {
					atomic.AddInt64(&errs, 1)
				}
				if ok {
					atomic.AddInt64(&wins, 1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if errs != 0 || wins != 1 {
			t.Fatalf("iteration %d: wins=%d errs=%d, want exactly one winner and no errors", i, wins, errs)
		}
	}
}

func TestKVConsumeSemantics(t *testing.T) {
	kv := NewKV(testdb.ScratchRedis(t), "t:")
	ctx := context.Background()

	if err := kv.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	b, ok, err := kv.Consume(ctx, "k")
	if err != nil || !ok || string(b) != "v" {
		t.Fatalf("first consume: got (%q, %v, %v), want (\"v\", true, nil)", b, ok, err)
	}
	if _, ok, err := kv.Consume(ctx, "k"); ok || err != nil {
		t.Fatalf("second consume: got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	if _, ok, err := kv.Get(ctx, "k"); ok || err != nil {
		t.Fatalf("get after consume: got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	if _, ok, err := kv.Consume(ctx, "never"); ok || err != nil {
		t.Fatalf("missing consume: got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}

func TestKVSetHonoursTTL(t *testing.T) {
	kv := NewKV(testdb.ScratchRedis(t), "t:")
	ctx := context.Background()

	if err := kv.Set(ctx, "k", []byte("v"), 50*time.Millisecond); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, ok, err := kv.Get(ctx, "k"); !ok || err != nil {
		t.Fatalf("get before expiry: got (ok=%v, err=%v)", ok, err)
	}
	time.Sleep(150 * time.Millisecond)
	if _, ok, err := kv.Get(ctx, "k"); ok || err != nil {
		t.Fatalf("get after expiry: got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	if _, ok, err := kv.Consume(ctx, "k"); ok || err != nil {
		t.Fatalf("consume after expiry: got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}

func TestKVDel(t *testing.T) {
	kv := NewKV(testdb.ScratchRedis(t), "t:")
	ctx := context.Background()
	if err := kv.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := kv.Del(ctx, "k"); err != nil {
		t.Fatalf("del: %v", err)
	}
	if _, ok, _ := kv.Get(ctx, "k"); ok {
		t.Fatal("key readable after Del")
	}
}
