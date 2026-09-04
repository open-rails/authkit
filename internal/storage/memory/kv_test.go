package memorystore

import (
	"context"
	"errors"
	"testing"
	"time"
)

// #305: expired entries are reclaimed by the sweep without anyone reading them.
func TestKVSweepsExpiredEntriesWithoutReads(t *testing.T) {
	kv := NewKV(WithSweepInterval(10 * time.Millisecond))
	defer kv.Close()
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		if err := kv.Set(ctx, "reset:"+string(rune('a'+i)), []byte("x"), 20*time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	if err := kv.Set(ctx, "live", []byte("x"), time.Hour); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for kv.Len() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("len=%d after the TTL elapsed, want only the live key", kv.Len())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// #305: the entry cap is a hard refusal, and an inline sweep of expired
// entries is tried first so a full store recovers on its own.
func TestKVEntryCapRefusesThenRecovers(t *testing.T) {
	kv := NewKV(WithMaxEntries(2), WithSweepInterval(0))
	ctx := context.Background()
	if err := kv.Set(ctx, "a", []byte("1"), 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := kv.Set(ctx, "b", []byte("2"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := kv.Set(ctx, "c", []byte("3"), time.Hour); !errors.Is(err, ErrKVFull) {
		t.Fatalf("third key err=%v, want ErrKVFull", err)
	}
	if err := kv.Set(ctx, "b", []byte("2b"), time.Hour); err != nil {
		t.Fatalf("overwriting a live key must not count against the cap: %v", err)
	}
	time.Sleep(15 * time.Millisecond)
	if err := kv.Set(ctx, "c", []byte("3"), time.Hour); err != nil {
		t.Fatalf("after 'a' expired the inline sweep must free a slot: %v", err)
	}
	if _, ok, _ := kv.Get(ctx, "a"); ok {
		t.Fatal("expired key must be gone")
	}
}

func TestKVCloseIsIdempotent(t *testing.T) {
	kv := NewKV(WithSweepInterval(time.Millisecond))
	kv.Close()
	kv.Close()
	if err := kv.Set(context.Background(), "k", []byte("v"), time.Hour); err != nil {
		t.Fatalf("a closed store still serves reads and writes: %v", err)
	}
}
