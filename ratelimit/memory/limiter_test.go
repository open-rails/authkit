package memorylimiter

import (
	"testing"
	"time"
)

func TestAllowNamedWithRetryAfterCooldown(t *testing.T) {
	limiter := New(map[string]Limit{
		"request_code": {Limit: 6, Window: time.Hour, Cooldown: time.Minute},
	})

	allowed, retryAfter, err := limiter.AllowNamedWithRetryAfter("request_code", "user")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed || retryAfter != 0 {
		t.Fatalf("first request allowed=%v retry_after=%s, want allowed with no retry_after", allowed, retryAfter)
	}

	allowed, retryAfter, err = limiter.AllowNamedWithRetryAfter("request_code", "user")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("second request was allowed during cooldown")
	}
	if retryAfter < 59*time.Second || retryAfter > time.Minute {
		t.Fatalf("retry_after=%s, want about 60s", retryAfter)
	}
}

func TestAllowNamedWithRetryAfterWindowUsesLongestReset(t *testing.T) {
	limiter := New(map[string]Limit{
		"request_code": {Limit: 1, Window: time.Hour, Cooldown: time.Minute},
	})

	allowed, _, err := limiter.AllowNamedWithRetryAfter("request_code", "user")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("first request denied")
	}

	allowed, retryAfter, err := limiter.AllowNamedWithRetryAfter("request_code", "user")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("second request was allowed")
	}
	if retryAfter < 59*time.Minute || retryAfter > time.Hour {
		t.Fatalf("retry_after=%s, want window reset around 1h", retryAfter)
	}
}
