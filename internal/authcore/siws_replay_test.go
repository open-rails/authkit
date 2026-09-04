package authcore

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/siws"
	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	redisstore "github.com/open-rails/authkit/internal/storage/redis"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
)

type noSNS struct{}

func (noSNS) ResolvePrimaryName(context.Context, string) (string, error) { return "", nil }

// #288/8: a genuinely signed challenge logs in exactly once; the identical
// signed message replayed within the TTL is refused because the nonce was
// consumed — on the memory cache and on Redis.
func TestVerifySIWSAndLoginConsumesChallengeOnce(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	signer, err := jwtkit.NewRSASigner(2048, "siws-replay")
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{
		Token: TokenConfig{Issuer: "https://test", IssuedAudiences: []string{"app"}, ExpectedAudiences: []string{"app"}},
	}, Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"siws-replay": signer.PublicKey()}},
		WithPostgres(pool), WithSolanaSNSResolver(noSNS{}))

	caches := map[string]func(t *testing.T) siws.ChallengeCache{
		"memory": func(t *testing.T) siws.ChallengeCache {
			c := memorystore.NewSIWSCache(15 * time.Minute)
			t.Cleanup(func() { _ = c.Close() })
			return c
		},
		"redis": func(t *testing.T) siws.ChallengeCache {
			return redisstore.NewSIWSCache(testdb.ScratchRedis(t), "", 0)
		},
	}
	for name, newCache := range caches {
		t.Run(name, func(t *testing.T) {
			cache := newCache(t)
			challenge, parsed, output := signedChallenge(t, "example.com", time.Now().UTC().Add(15*time.Minute))
			if err := cache.Put(ctx, parsed.Nonce, challenge); err != nil {
				t.Fatalf("store challenge: %v", err)
			}

			access, _, refresh, userID, created, err := svc.VerifySIWSAndLogin(ctx, cache, output, nil)
			if err != nil {
				t.Fatalf("first login: %v", err)
			}
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, userID) })
			if !created || access == "" || refresh == "" {
				t.Fatalf("first login: created=%v access=%v refresh=%v", created, access != "", refresh != "")
			}

			_, _, _, _, _, err = svc.VerifySIWSAndLogin(ctx, cache, output, nil)
			if !errors.Is(err, ErrSIWSChallengeNotFound) {
				t.Fatalf("replayed signature: err=%v, want ErrSIWSChallengeNotFound", err)
			}
			if _, found, _ := cache.Get(ctx, parsed.Nonce); found {
				t.Fatal("nonce still present after the login consumed it")
			}
		})
	}
}
