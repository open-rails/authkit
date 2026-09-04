package redisstore

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
)

// #307: two stores with different prefixes on one Redis database never see
// each other's keys.
func TestKVPrefixIsolatesKeyspaces(t *testing.T) {
	rdb := testdb.ScratchRedis(t)
	ctx := context.Background()
	a := NewKV(rdb, "authkit:tenant_a:")
	b := NewKV(rdb, "authkit:tenant_b:")

	if err := a.Set(ctx, "password_reset:token:h1", []byte("a"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := b.Set(ctx, "password_reset:token:h1", []byte("b"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := a.Get(ctx, "password_reset:token:h1"); !ok || string(v) != "a" {
		t.Fatalf("a got %q ok=%v", v, ok)
	}
	if _, ok, _ := a.Consume(ctx, "password_reset:token:h1"); !ok {
		t.Fatal("a must consume its own key")
	}
	if v, ok, _ := b.Get(ctx, "password_reset:token:h1"); !ok || string(v) != "b" {
		t.Fatalf("b's key must survive a's consume; got %q ok=%v", v, ok)
	}
	keys, err := rdb.Keys(ctx, "authkit:tenant_b:*").Result()
	if err != nil || len(keys) != 1 || keys[0] != "authkit:tenant_b:password_reset:token:h1" {
		t.Fatalf("tenant_b keys=%v err=%v", keys, err)
	}
	if keys, _ := rdb.Keys(ctx, "authkit:tenant_a:*").Result(); len(keys) != 0 {
		t.Fatalf("tenant_a keys after consume=%v", keys)
	}
}
