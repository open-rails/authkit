package authhttp

import (
	"context"
	"fmt"
	"testing"

	"github.com/open-rails/authkit/internal/testdb"

	"github.com/stretchr/testify/require"
)

// Real Postgres failures: a store that can hold a challenge but cannot read
// or claim it, and a failing factor write. None should be presented as a
// mistyped OTP.
func TestMFAEnrollmentBackendFailures(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	f := newAccountFlow(t, pg.Pool, newServerTestConfig())
	for _, method := range []string{"totp", "sms"} {
		for _, failure := range []string{"read", "claim", "persistence"} {
			t.Run(method+"/"+failure, func(t *testing.T) {
				f.t = t
				user, err := f.service.svc.CreateUser(ctx, uniqueEmail("mfa-backend"), "mfaback"+uniqueSuffix())
				require.NoError(t, err)
				require.NoError(t, f.service.svc.MarkEmailVerified(ctx, user.ID))
				require.NoError(t, f.service.svc.AdminSetPassword(ctx, user.ID, "Correct-horse-battery-1"))
				session := f.expect(200, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": "Correct-horse-battery-1"})).AccessToken
				body := map[string]any{"method": method}
				if method == "sms" {
					body["phone"] = uniquePhone()
				}
				start := f.request("POST", "/user/2fa", session, body)
				if method == "totp" {
					f.expect(200, start)
				} else {
					f.expect(202, start)
				}
				body["code"] = "not-a-code"
				invalid := f.expect(400, f.request("POST", "/user/2fa", session, body))
				require.Equal(t, "invalid_code", invalid.Error.Code)
				proof := func() {
					if method == "totp" {
						body["code"] = flowTOTP(t, start.Secret)
					} else {
						body["code"] = f.sms.verificationCode(t)
					}
				}
				proof()
				restore := func() {}
				switch failure {
				case "read":
					restore = takeEphemeralOffline(t, pg.Pool)
				case "claim":
					restore = failEphemeralClaims(t, pg.Pool, "")
				case "persistence":
					_, err := pg.Pool.Exec(ctx, `CREATE FUNCTION mfa_backend_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected factor persistence failure'; END $$; CREATE TRIGGER mfa_backend_failure BEFORE INSERT ON mfa_factors FOR EACH ROW EXECUTE FUNCTION mfa_backend_failure()`)
					require.NoError(t, err)
					restore = func() {
						_, err := pg.Pool.Exec(ctx, `DROP TRIGGER mfa_backend_failure ON mfa_factors; DROP FUNCTION mfa_backend_failure()`)
						require.NoError(t, err)
					}
				}
				defer func() { restore() }()
				failed := f.expect(500, f.request("POST", "/user/2fa", session, body))
				require.Equal(t, "internal_error", failed.Error.Code)
				factors, err := fixtureBackend(f.service.svc).List2FAFactors(ctx, user.ID)
				require.NoError(t, err)
				require.Empty(t, factors)
				restore()
				restore = func() {}
				if failure == "persistence" {
					// A successful claim stays single-use even when the SQL transaction fails.
					delete(body, "code")
					start = f.request("POST", "/user/2fa", session, body)
					if method == "totp" {
						f.expect(200, start)
					} else {
						f.expect(202, start)
					}
				}
				proof()
				f.expect(200, f.request("POST", "/user/2fa", session, body))
				factors, err = fixtureBackend(f.service.svc).List2FAFactors(ctx, user.ID)
				require.NoError(t, err)
				require.Len(t, factors, 1, fmt.Sprint(method, " must recover after ", failure))
			})
		}
	}
}
