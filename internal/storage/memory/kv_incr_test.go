package memorystore

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"
)

// Incr must hand every one of many racing callers a distinct consecutive value
// (#306): that is what makes a wrong-guess cap fire on the Nth concurrent guess.
func TestKVIncrDistinctUnderConcurrency(t *testing.T) {
	kv := NewKV()
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

// The TTL is set when the counter is created and never extended by later
// increments, so a guesser cannot keep a counter alive by guessing.
func TestKVIncrTTLSetOnce(t *testing.T) {
	kv := NewKV()
	ctx := context.Background()

	if n, err := kv.Incr(ctx, "k", 40*time.Millisecond); err != nil || n != 1 {
		t.Fatalf("first incr: (%d, %v)", n, err)
	}
	time.Sleep(25 * time.Millisecond)
	if n, err := kv.Incr(ctx, "k", 40*time.Millisecond); err != nil || n != 2 {
		t.Fatalf("second incr: (%d, %v)", n, err)
	}
	if b, ok, _ := kv.Get(ctx, "k"); !ok || string(b) != "2" {
		t.Fatalf("counter readable as integer string: (%q, %v)", b, ok)
	}
	time.Sleep(25 * time.Millisecond)
	if _, ok, _ := kv.Get(ctx, "k"); ok {
		t.Fatal("second increment must not extend the original TTL")
	}
	if n, err := kv.Incr(ctx, "k", time.Minute); err != nil || n != 1 {
		t.Fatalf("incr after expiry must restart at 1: (%d, %v)", n, err)
	}
}
