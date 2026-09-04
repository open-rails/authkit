package redisstore

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
)

// Incr must hand every one of many racing callers a distinct consecutive value
// (#306): INCR+PEXPIRE run as one server-side script, so no two guesses can
// observe the same count.
func TestKVIncrDistinctUnderConcurrency(t *testing.T) {
	kv := NewKV(testdb.ScratchRedis(t))
	ctx := context.Background()
	const racers = 64

	values := make([]int64, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for r := 0; r < racers; r++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			n, err := kv.Incr(ctx, "attempts", time.Minute)
			if err != nil {
				t.Errorf("incr: %v", err)
			}
			values[i] = n
		}(r)
	}
	close(start)
	wg.Wait()

	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	for i, v := range values {
		if v != int64(i+1) {
			t.Fatalf("values are not 1..%d: %v", racers, values)
		}
	}
}

// The expiry is set only when the counter is created; later increments must not
// push it out.
func TestKVIncrTTLSetOnce(t *testing.T) {
	rdb := testdb.ScratchRedis(t)
	kv := NewKV(rdb)
	ctx := context.Background()

	if n, err := kv.Incr(ctx, "k", 10*time.Second); err != nil || n != 1 {
		t.Fatalf("first incr: (%d, %v)", n, err)
	}
	time.Sleep(300 * time.Millisecond)
	if n, err := kv.Incr(ctx, "k", 10*time.Second); err != nil || n != 2 {
		t.Fatalf("second incr: (%d, %v)", n, err)
	}
	ttl, err := rdb.PTTL(ctx, "k").Result()
	if err != nil {
		t.Fatalf("pttl: %v", err)
	}
	if ttl <= 0 || ttl > 10*time.Second-250*time.Millisecond {
		t.Fatalf("second increment must not reset the TTL: pttl=%v", ttl)
	}
	if b, ok, _ := kv.Get(ctx, "k"); !ok || string(b) != "2" {
		t.Fatalf("counter readable as integer string: (%q, %v)", b, ok)
	}
}
