package testdb

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisLeaseKey = "authkit:testdb:lease"

// ScratchRedis returns a client on a private logical database of the Redis named
// by AUTHKIT_TEST_REDIS_URL: one of the server's 16 DBs is leased with SET NX so
// concurrent test binaries never share a keyspace, and the DB is flushed on
// cleanup. Skips, or fails under AUTHKIT_TEST_REQUIRE_DB=1, when the URL is unset.
func ScratchRedis(t testing.TB) *redis.Client {
	t.Helper()
	opts, err := redis.ParseURL(requireEnv(t, "AUTHKIT_TEST_REDIS_URL"))
	if err != nil {
		t.Fatalf("parse AUTHKIT_TEST_REDIS_URL: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	owner := strconv.Itoa(os.Getpid())
	for db := 0; db < 16; db++ {
		o := *opts
		o.DB = db
		c := redis.NewClient(&o)
		leased, err := c.SetNX(ctx, redisLeaseKey, owner, 10*time.Minute).Result()
		if err != nil {
			_ = c.Close()
			t.Fatalf("redis %s db %d: %v", opts.Addr, db, err)
		}
		if !leased {
			_ = c.Close()
			continue
		}
		t.Cleanup(func() {
			_ = c.FlushDB(context.Background()).Err()
			_ = c.Close()
		})
		return c
	}
	t.Fatalf("redis %s: all 16 databases are leased", opts.Addr)
	return nil
}
