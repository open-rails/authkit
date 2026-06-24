package authcore

import (
	"sync"
	"testing"
	"time"
)

// TestLastUsedThrottle_Window: a key writes at most once per window; the window
// resets after it elapses; distinct keys are independent.
func TestLastUsedThrottle_Window(t *testing.T) {
	tr := newLastUsedThrottle(60 * time.Second)
	t0 := time.Unix(1_700_000_000, 0)

	if !tr.allow("k1", t0) {
		t.Fatal("first touch of k1 must be allowed")
	}
	if tr.allow("k1", t0.Add(10*time.Second)) {
		t.Fatal("k1 within window must be coalesced (denied)")
	}
	if tr.allow("k1", t0.Add(59*time.Second)) {
		t.Fatal("k1 still within window must be coalesced")
	}
	if !tr.allow("k1", t0.Add(60*time.Second)) {
		t.Fatal("k1 after the window must be allowed again")
	}
	// A different key is independent of k1's window.
	if !tr.allow("k2", t0.Add(10*time.Second)) {
		t.Fatal("first touch of k2 must be allowed")
	}
}

// TestLastUsedThrottle_ConcurrentSingleWinner: concurrent touches of one key at the
// same instant let exactly one write through.
func TestLastUsedThrottle_ConcurrentSingleWinner(t *testing.T) {
	tr := newLastUsedThrottle(60 * time.Second)
	now := time.Unix(1_700_000_000, 0)

	const n = 16
	var wg sync.WaitGroup
	allowed := make([]bool, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			allowed[i] = tr.allow("hot", now)
		}(i)
	}
	wg.Wait()

	wins := 0
	for _, a := range allowed {
		if a {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent touches of one key at one instant: want 1 write, got %d", wins)
	}
}
