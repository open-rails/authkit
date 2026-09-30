package securitytest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	kdf "github.com/open-rails/authkit/internal/password"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
)

// TestSecurityPasswordHashingIsBounded (ak#417): password checks share one
// process-wide hashing budget, so a flood of wrong-password sign-ins never
// holds more hashing memory than the budget allows. Past a brief wait the
// excess is turned away with a retryable 503 server_busy and Retry-After.
func TestSecurityPasswordHashingIsBounded(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	ctx := context.Background()
	a := h.newAccount("kdfflood")
	// The costliest Argon2id a stored (imported) hash may name: 256 MiB, 4 passes.
	const heavyKiB, heavyPasses = 256 * 1024, 4
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	sum := argon2.IDKey([]byte(password), salt, heavyPasses, heavyKiB, 1, 32)
	heavy := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=1$%s$%s", heavyKiB, heavyPasses,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
	_, err := h.pool.Exec(ctx, `UPDATE profiles.user_passwords SET password_hash=$1, hash_algo='argon2id' WHERE user_id=$2::uuid`, heavy, a.id)
	require.NoError(t, err)

	type answer struct {
		status     int
		code       string
		retryAfter string
		err        error
	}
	login := func(pass string) answer {
		body, _ := json.Marshal(map[string]string{"identifier": a.email, "password": pass})
		resp, err := http.Post(h.server.URL+apiPrefix+"/password/login", "application/json", bytes.NewReader(body))
		if err != nil {
			return answer{err: err}
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return answer{status: resp.StatusCode, code: response{body: raw}.errorCode(), retryAfter: resp.Header.Get("Retry-After")}
	}

	limit := kdf.InFlightLimit()
	n := 4*int(limit/(heavyKiB<<10)) + 4
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak uint64
	stop, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			runtime.ReadMemStats(&m)
			peak = max(peak, m.HeapAlloc)
		}
	}()
	answers := make([]answer, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { answers[i] = login(fmt.Sprintf("Wrong-password-%d", i)) })
	}
	wg.Wait()
	close(stop)
	<-sampled

	busy := 0
	for _, got := range answers {
		require.NoError(t, got.err)
		switch got.status {
		case http.StatusUnauthorized:
			require.Equal(t, "invalid_credentials", got.code)
		case http.StatusServiceUnavailable:
			require.Equal(t, "server_busy", got.code)
			require.Equal(t, "1", got.retryAfter)
			busy++
		default:
			t.Fatalf("a flooded sign-in answered %d %s", got.status, got.code)
		}
	}
	grew := int64(peak) - int64(base.HeapAlloc)
	require.Less(t, grew, 2*limit+128<<20, "%d concurrent sign-ins held %d MiB (limit %d MiB)", n, grew>>20, limit>>20)
	require.NotZero(t, busy, "no sign-in was turned away")

	t.Run("control: the owner signs in once the flood is over", func(t *testing.T) {
		got := login(password)
		require.NoError(t, got.err)
		require.Equal(t, http.StatusOK, got.status, got.code)
	})
}
