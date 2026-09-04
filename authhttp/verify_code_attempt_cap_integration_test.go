package authhttp

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

// #306: the per-email wrong-code cap must hold under concurrent submissions.
// The old GET-then-SET counter let K parallel guesses all read the same n, so
// the 5-attempt invalidation never fired. Proven on real handlers + Postgres
// against both the memory store and a real Redis.
func TestEmailVerifyConfirm_AttemptCapHoldsUnderConcurrency(t *testing.T) {
	forEachStore(t, func(t *testing.T, store ephemeralStore) {
		pool := newServerTestPool(t)
		ctx := context.Background()
		emailSender := &captureEmailSender{}
		opts := append(store.engineOpts(), embedded.WithEmailSender(emailSender))
		srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool, opts...), WithoutRateLimiter())
		require.NoError(t, err)

		newVerification := func(prefix string) (email, code string) {
			email = uniqueEmail(prefix)
			u, err := srv.svc.CreateUser(ctx, email, "cap"+uniqueSuffix())
			require.NoError(t, err)
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })
			w := serveJSON(srv, http.MethodPost, "/email/verify/request", `{"email":"`+email+`"}`)
			require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
			code = emailSender.verificationCode(t)
			wrong := "000000"
			if code == wrong {
				wrong = "000001"
			}
			return email, wrong
		}
		guessConcurrently := func(email, wrong string, n int) {
			var unexpected int64
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					w := serveJSON(srv, http.MethodPost, "/email/verify/confirm", `{"code":"`+wrong+`","email":"`+email+`"}`)
					if w.Code != http.StatusBadRequest {
						atomic.AddInt64(&unexpected, 1)
					}
				}()
			}
			close(start)
			wg.Wait()
			require.Zero(t, unexpected, "every wrong guess must be rejected")
		}

		// Below the cap, concurrent guesses are counted exactly and the code survives.
		email, wrong := newVerification("cap-below")
		guessConcurrently(email, wrong, 4)
		if store.rdb != nil {
			n, err := store.rdb.Get(ctx, "auth:email_verify:attempts:"+email).Int()
			require.NoError(t, err)
			require.Equal(t, 4, n, "four concurrent wrong guesses must count as exactly four")
		}
		code := emailSender.verificationCode(t)
		w := serveJSON(srv, http.MethodPost, "/email/verify/confirm", `{"code":"`+code+`","email":"`+email+`"}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		// At or past the cap, concurrent guesses invalidate the outstanding code.
		email, wrong = newVerification("cap-over")
		code = emailSender.verificationCode(t)
		guessConcurrently(email, wrong, 50)
		w = serveJSON(srv, http.MethodPost, "/email/verify/confirm", `{"code":"`+code+`","email":"`+email+`"}`)
		require.Equal(t, http.StatusBadRequest, w.Code, "the correct code must be dead once the cap is hit under concurrency")
	})
}
