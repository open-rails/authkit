package memorylimiter

import (
	"testing"
	"time"

	"github.com/open-rails/authkit/ratelimit"
)

// #305: at the bucket cap a NEW key is denied (fail closed) unless an inline
// sweep of aged-out buckets frees room; known keys keep working.
func TestMaxBucketsDeniesNewKeysWhenFull(t *testing.T) {
	limits := map[string]ratelimit.Limit{"login": {Limit: 5, Window: 50 * time.Millisecond}}
	l := New(limits, WithMaxBuckets(2))

	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		if ok, err := l.AllowNamed("login", ip); err != nil || !ok {
			t.Fatalf("ip %s: ok=%v err=%v", ip, ok, err)
		}
	}
	res, err := l.AllowNamedResult("login", "10.0.0.3")
	if err != nil || res.Allowed || res.Reason != ratelimit.ReasonLimitExceeded {
		t.Fatalf("third key at cap: %+v err=%v, want denied", res, err)
	}
	if ok, err := l.AllowNamed("login", "10.0.0.1"); err != nil || !ok {
		t.Fatalf("known key at cap must still be served: ok=%v err=%v", ok, err)
	}
	if l.Len() != 2 {
		t.Fatalf("len=%d, want 2", l.Len())
	}

	time.Sleep(60 * time.Millisecond)
	if ok, err := l.AllowNamed("login", "10.0.0.3"); err != nil || !ok {
		t.Fatalf("after the window the inline sweep must admit the new key: ok=%v err=%v", ok, err)
	}
	if l.Len() != 1 {
		t.Fatalf("len=%d after sweep, want 1", l.Len())
	}
}
