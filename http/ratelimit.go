package authhttp

import (
	"net"
	"net/http"
)

// RateLimiter is a minimal interface used by adapters.
type RateLimiter interface {
	AllowNamed(bucket string, key string) (bool, error)
}

// AllowNamed applies a per-IP limit using the provided bucket name.
// It fails open on limiter error.
func AllowNamed(r *http.Request, rl RateLimiter, bucket string) bool {
	if rl == nil {
		return true
	}
	ip := clientIP(r)
	key := "auth:" + bucket + ":ip:" + ip
	ok, err := rl.AllowNamed(bucket, key)
	if err != nil {
		return true
	}
	return ok
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	// Conservative: prefer RemoteAddr (works for local/dev and typical reverse proxy setups when trusted layer overwrites).
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
