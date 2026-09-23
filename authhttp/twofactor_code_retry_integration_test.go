package authhttp

import (
	"sync"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// #387: a wrong email/SMS code keeps the stored code, a correct one is spent
// exactly once, and the fifth miss burns it. Login and step-up both.
func TestTwoFactorCodeSurvivesWrongGuess(t *testing.T) {
	forEachStore(t, func(t *testing.T, store ephemeralStore) {
		ctx := t.Context()
		f := newAccountFlow(t, testdb.Pool(t), store, newServerTestConfig())
		const pass = "Correct-horse-battery-1"
		email := uniqueEmail("code-retry")
		user, err := f.service.svc.CreateUser(ctx, email, "coderetry"+uniqueSuffix())
		require.NoError(t, err)
		require.NoError(t, f.service.svc.AdminSetPassword(ctx, user.ID, pass))
		require.NoError(t, f.service.svc.MarkEmailVerified(ctx, user.ID))
		_, err = fixtureBackend(f.service.svc).Enable2FA(ctx, user.ID, "email", nil, embedded.AllowAdditionalFactors)
		require.NoError(t, err)

		login := func() (map[string]any, string) {
			t.Helper()
			ch := f.expect(403, f.post("/password/login", map[string]any{"identifier": email, "password": pass}))
			require.Equal(t, "email", ch.Error.Metadata.Method)
			return map[string]any{"user_id": user.ID, "challenge": ch.Error.Metadata.Challenge}, f.email.lastLoginCode()
		}
		verify := func(body map[string]any, code string) flowResponse {
			req := map[string]any{"code": code}
			for k, v := range body {
				req[k] = v
			}
			return f.post("/2fa/verify", req)
		}
		wrong := func(code string) string {
			if code[0] == '0' {
				return "1" + code[1:]
			}
			return "0" + code[1:]
		}
		concurrent := func(n int, do func() flowResponse) (ok, denied int) {
			var mu sync.Mutex
			var wg sync.WaitGroup
			for range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					r := do()
					mu.Lock()
					defer mu.Unlock()
					if r.status == 200 {
						ok++
					} else if r.status == 401 {
						denied++
					}
				}()
			}
			wg.Wait()
			return ok, denied
		}

		// Login: a typo keeps the code.
		body, code := login()
		f.expect(401, verify(body, wrong(code)))
		signed := f.expect(200, verify(body, code))
		f.session(signed.TokenSet, "pwd", "email", "otp", "mfa")
		f.expect(401, verify(body, code))

		// Login: concurrent correct submissions succeed exactly once.
		body, code = login()
		ok, denied := concurrent(8, func() flowResponse { return verify(body, code) })
		require.Equal(t, 1, ok)
		require.Equal(t, 7, denied)

		// Login: four misses leave the code usable; the fifth burns it.
		body, code = login()
		for range 4 {
			f.expect(401, verify(body, wrong(code)))
		}
		f.expect(200, verify(body, code))
		body, code = login()
		for range 5 {
			f.expect(401, verify(body, wrong(code)))
		}
		f.expect(401, verify(body, code))
		// The default 3-session cap has evicted the first session by now.
		latest := f.expect(200, verify(login()))

		// Step-up on the signed-in session: same rules, the code CAS is the only guard.
		access := latest.TokenSet.AccessToken
		stepUp := func(code string) flowResponse {
			return f.request("POST", "/step-up/2fa", access, map[string]any{"code": code})
		}
		send := func() string {
			t.Helper()
			ch := f.expect(403, f.request("POST", "/step-up/2fa", access, map[string]any{}))
			require.Equal(t, "2fa_required", ch.Error.Code)
			return f.email.lastLoginCode()
		}
		code = send()
		f.expect(401, stepUp(wrong(code)))
		f.expect(200, stepUp(code))
		f.expect(401, stepUp(code))

		code = send()
		ok, denied = concurrent(8, func() flowResponse { return stepUp(code) })
		require.Equal(t, 1, ok)
		require.Equal(t, 7, denied)

		code = send()
		for range 5 {
			f.expect(401, stepUp(wrong(code)))
		}
		f.expect(401, stepUp(code))
		code = send()
		f.expect(200, stepUp(code))
	})
}
