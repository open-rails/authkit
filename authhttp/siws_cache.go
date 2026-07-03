package authhttp

import (
	"time"

	"github.com/open-rails/authkit/siws"
	memorystore "github.com/open-rails/authkit/storage/memory"
	redisstore "github.com/open-rails/authkit/storage/redis"
)

func (s *Service) siwsCache() siws.ChallengeCache {
	if s.rd != nil {
		return redisstore.NewSIWSCache(s.rd, "auth:siws:nonce:", 15*time.Minute)
	}
	// Memoize the in-memory cache so the challenge Put and the later Consume hit
	// the SAME instance. A fresh cache per call would lose every pending
	// challenge (breaking Solana login/link without Redis) and leak a cleanup
	// goroutine on each request. Mirrors stateCache (#196).
	if s.memSIWSCache == nil {
		s.memSIWSCache = memorystore.NewSIWSCache(15 * time.Minute)
	}
	return s.memSIWSCache
}
