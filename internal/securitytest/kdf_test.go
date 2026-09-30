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
	a := h.heavyHashAccount("kdfflood")
	login := func(pass string) answer { return h.rawLogin(a, pass) }

	limit := kdf.InFlightLimit()
	n := floodSize()
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
	require.Less(t, grew, 2*limit+256<<20, "%d concurrent sign-ins held %d MiB (limit %d MiB)", n, grew>>20, limit>>20)
	require.NotZero(t, busy, "no sign-in was turned away")

	t.Run("control: the owner signs in once the flood is over", func(t *testing.T) {
		got := login(password)
		require.NoError(t, got.err)
		require.Equal(t, http.StatusOK, got.status, got.code)
	})
}

// A password change the hashing budget can't take in time is 503 server_busy
// with Retry-After, like a sign-in, never masked as another error.
func TestSecurityPasswordChangeUnderHashingLoad(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	flooder := h.heavyHashAccount("kdfchangeflood")
	a := h.newAccount("kdfchange")
	token := h.login(a).AccessToken
	change := func() response {
		return h.do(request{method: http.MethodPut, path: "/me/password", token: token, body: map[string]string{"new_password": "Flooded-long-passphrase-1"}})
	}

	// Sign-ins that each need the costliest hash keep the budget full, with
	// more queued ahead of the change.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range floodSize() {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					h.rawLogin(flooder, "Wrong-password")
				}
			}
		})
	}
	time.Sleep(300 * time.Millisecond)
	busy := change()
	close(stop)
	wg.Wait()
	require.Equal(t, http.StatusServiceUnavailable, busy.status, busy.String())
	require.Equal(t, "server_busy", busy.errorCode())
	require.Equal(t, "1", busy.header.Get("Retry-After"))

	resp := change()
	require.Equal(t, http.StatusNoContent, resp.status, "the change goes through once the flood is over: %s", resp)
}

// heavyKiB and heavyPasses are the costliest Argon2id a stored (imported)
// hash may name: 256 MiB, 4 passes.
const heavyKiB, heavyPasses = 256 * 1024, 4

// floodSize is enough concurrent heavy sign-ins to fill the hashing budget
// four times over.
func floodSize() int { return 4*int(kdf.InFlightLimit()/(heavyKiB<<10)) + 4 }

// heavyHashAccount is a password account whose stored hash is the costliest
// one accepted.
func (h *host) heavyHashAccount(prefix string) account {
	h.t.Helper()
	a := h.newAccount(prefix)
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	sum := argon2.IDKey([]byte(password), salt, heavyPasses, heavyKiB, 1, 32)
	heavy := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=1$%s$%s", heavyKiB, heavyPasses,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
	_, err := h.pool.Exec(context.Background(), `UPDATE profiles.user_passwords SET password_hash=$1, hash_algo='argon2id' WHERE user_id=$2::uuid`, heavy, a.id)
	require.NoError(h.t, err)
	return a
}

type answer struct {
	status     int
	code       string
	retryAfter string
	err        error
}

// rawLogin is a password sign-in safe to run off the test goroutine.
func (h *host) rawLogin(a account, pass string) answer {
	body, _ := json.Marshal(map[string]string{"identifier": a.email, "password": pass})
	resp, err := http.Post(h.server.URL+apiPrefix+"/password/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return answer{err: err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return answer{status: resp.StatusCode, code: response{body: raw}.errorCode(), retryAfter: resp.Header.Get("Retry-After")}
}
