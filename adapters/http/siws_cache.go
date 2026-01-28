package authhttp

import (
	"time"

	"github.com/PaulFidika/authkit/siws"
	memorystore "github.com/PaulFidika/authkit/storage/memory"
	redisstore "github.com/PaulFidika/authkit/storage/redis"
)

func (s *Service) siwsCache() siws.ChallengeCache {
	if s.rd != nil {
		return redisstore.NewSIWSCache(s.rd, "auth:siws:nonce:", 15*time.Minute)
	}
	return memorystore.NewSIWSCache(15 * time.Minute)
}
