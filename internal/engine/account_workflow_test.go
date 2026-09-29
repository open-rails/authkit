package engine

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testoutbox"
	"github.com/stretchr/testify/require"
)

func TestAccountAdmissionWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.Registration.PasswordlessLogin, cfg.Registration.PasswordlessAutoRegistration = true, true
	cfg.Registration.Verification = iam.RegistrationVerificationRequired
	cfg.Registration.NativeUserMode = iam.RegistrationModeInviteOnly
	f := newAccountFlow(t, pg.Pool, cfg)
	ctx := context.Background()
	inviter, _ := createAccountInvite(t, f.service, pg.Pool, uniqueEmail("unused"))
	for _, phone := range []bool{false, true} {
		for _, passwordless := range []bool{false, true} {
			name := fmt.Sprintf("phone=%t/passwordless=%t", phone, passwordless)
			t.Run(name, func(t *testing.T) {
				f.t = t
				identifier := uniqueEmail("admission")
				channel, method := "email", "email"
				if phone {
					identifier = uniquePhone()
					channel, method = "phone", "sms"
				}
				start, confirm := "/register", "/verify/confirm"
				body := map[string]any{"identifier": identifier, "username": "admit" + uniqueSuffix(), "password": "Correct-horse-battery-1"}
				if passwordless {
					start, confirm = "/passwordless/start", "/passwordless/confirm"
					delete(body, "username")
					delete(body, "password")
					body["mode"] = "both"
					body["return_to"] = "/checkout?plan=pro"
					channel = method
				}
				f.expect(403, f.post(start, body))
				invite, err := f.service.Backend().CreateAccountInvite(ctx, iam.UserActor(inviter), iam.NewAccountInvite{Email: uniqueEmail("invite")})
				require.NoError(t, err)
				require.Equal(t, invite.URL, lastSent(f.email, testoutbox.AccountInvite).Link)
				body["account_invite_token"] = invite.Code
				f.expect(202, f.post(start, body))
				if !passwordless {
					f.expect(401, f.post("/password/login", map[string]any{"identifier": identifier, "password": "wrong"}))
					recovery := f.expect(403, f.post("/password/login", map[string]any{"identifier": identifier, "password": "Correct-horse-battery-1"}))
					require.Equal(t, "verification_required", recovery.Error.Code)
				}

				code := f.verifyCode(phone)
				rawURL := f.verifyURL(phone)
				path := "/verify"
				if passwordless {
					path = "/login/link"
				}
				link := f.deliveredLink(rawURL, path, channel)
				// A code bound to this target cannot authenticate another target, and a
				// failed guess does not consume either representation of the live proof.
				f.expect(401, f.post(confirm, map[string]any{"identifier": uniqueEmail("wrong-target"), "code": code}))
				f.expect(401, f.post(confirm, map[string]any{"identifier": identifier, "code": "WRONG"}))
				var replies [2]flowResponse
				var wg sync.WaitGroup
				for i := range replies {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						proof := map[string]any{"identifier": identifier, "code": code}
						if i == 1 {
							proof = map[string]any{"token": link}
						}
						replies[i] = f.post(confirm, proof)
					}(i)
				}
				wg.Wait()
				winners := 0
				var tokens iam.TokenSet
				for i, reply := range replies {
					if reply.status == 200 {
						winners++
						tokens = reply.TokenSet
						if passwordless {
							tokens = reply.Tokens
							require.Equal(t, "/checkout?plan=pro", reply.ReturnTo)
						}
					} else {
						require.Equal(t, [2]int{401, 400}[i], reply.status, reply.raw) // spent code, spent link
					}
				}
				require.Equal(t, 1, winners)
				f.session(tokens, method)
				var uid string
				var verified, hasPassword bool
				require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT u.id::text, CASE WHEN $2 THEN u.phone_verified ELSE u.email_verified END, EXISTS(SELECT 1 FROM user_passwords p WHERE p.user_id=u.id) FROM users u WHERE CASE WHEN $2 THEN u.phone_number=$1 ELSE u.email=$1 END`, identifier, phone).Scan(&uid, &verified, &hasPassword))
				require.True(t, verified)
				require.Equal(t, !passwordless, hasPassword)
				requireAccountInviteConsumed(t, pg.Pool, invite.ID, uid)
				f.expect(400, f.post(confirm, map[string]any{"token": link}))
				if !passwordless {
					f.expect(200, f.post("/password/login", map[string]any{"identifier": identifier, "password": "Correct-horse-battery-1"}))
					f.expect(200, f.post("/password/login", map[string]any{"identifier": body["username"], "password": "Correct-horse-battery-1"}))
					taken := f.expect(400, f.post("/register", body))
					require.Equal(t, "username_in_use", taken.Error.Code)
				}
			})
		}
	}
	f.t = t
	// Admission is checked again inside account creation, after delivery. A
	// revoked invitation must leave no account or password behind.
	for _, start := range []string{"/register", "/passwordless/start"} {
		email := uniqueEmail("revoked")
		invite, err := f.service.Backend().CreateAccountInvite(ctx, iam.UserActor(inviter), iam.NewAccountInvite{Email: email})
		require.NoError(t, err)
		payload := map[string]any{"identifier": email, "account_invite_token": invite.Code}
		if start == "/register" {
			payload["username"] = "revoked" + uniqueSuffix()
			payload["password"] = "Correct-horse-battery-1"
		} else {
			payload["mode"] = "both"
		}
		f.expect(202, f.post(start, payload))
		code := sentCode(t, f.email, testoutbox.Verification)
		_, err = pg.Pool.Exec(ctx, `UPDATE account_registration_invites SET revoked_at=now() WHERE id=$1::uuid`, invite.ID)
		require.NoError(t, err)
		confirm := "/verify/confirm"
		if start == "/passwordless/start" {
			confirm = "/passwordless/confirm"
		}
		reply := f.post(confirm, map[string]any{"identifier": email, "code": code})
		require.GreaterOrEqual(t, reply.status, 400, reply.raw)
		var count int
		require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email=$1`, email).Scan(&count))
		require.Zero(t, count)
	}
	for _, body := range []map[string]any{{"identifier": "not-an-identifier", "username": "validname", "password": "Correct-horse-battery-1"}, {"identifier": uniqueEmail("weak"), "username": "validname", "password": "short"}} {
		f.expect(400, f.post("/register", body))
	}

	// Unknown contacts remain undisclosed when automatic signup is disabled.
	disabled := newServerTestConfig()
	noPasswordless := newAccountFlow(t, pg.Pool, disabled)
	noPasswordless.expect(404, noPasswordless.post("/passwordless/start", map[string]any{"identifier": uniqueEmail("disabled")}))
	disabled.Registration.PasswordlessLogin = true
	noSignup := newAccountFlow(t, pg.Pool, disabled)
	noSignup.expect(202, noSignup.post("/passwordless/start", map[string]any{"identifier": uniqueEmail("unknown")}))
	require.Empty(t, lastSent(noSignup.email, testoutbox.Verification).Code)
	// Generated usernames avoid an existing account's claim.
	username := "collision" + uniqueSuffix()
	_, err := fixtureBackend(f.service.Backend()).createUser(ctx, uniqueEmail("collision"), username)
	require.NoError(t, err)
	collisionEmail := username + "@example.com"
	invite, err := f.service.Backend().CreateAccountInvite(ctx, iam.UserActor(inviter), iam.NewAccountInvite{Email: collisionEmail})
	require.NoError(t, err)
	f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": collisionEmail, "mode": "code", "account_invite_token": invite.Code}))
	f.expect(200, f.post("/passwordless/confirm", map[string]any{"identifier": collisionEmail, "code": sentCode(t, f.email, testoutbox.Verification)}))
	created, err := fixtureBackend(f.service.Backend()).getUserByEmail(ctx, collisionEmail)
	require.NoError(t, err)
	require.NotEqual(t, username, *created.Username)

	testRegistrationRollback(f, inviter)
	testProofLifecycle(f)
}

func testRegistrationRollback(f *accountFlow, inviter string) {
	t, pool, ctx := f.t, fixtureBackend(f.service.Backend()).pg, f.t.Context()
	_, err := pool.Exec(ctx, `CREATE FUNCTION registration_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected invite consume failure'; END $$; CREATE TRIGGER registration_failure BEFORE UPDATE OF consumed_at ON account_registration_invites FOR EACH ROW EXECUTE FUNCTION registration_failure()`)
	require.NoError(t, err)
	defer func() {
		_, err := pool.Exec(ctx, `DROP TRIGGER registration_failure ON account_registration_invites; DROP FUNCTION registration_failure()`)
		require.NoError(t, err)
	}()
	for _, flow := range []string{"email", "sms", "passwordless", "oidc", "oauth2"} {
		email, identifier := uniqueEmail("rollback"), ""
		identifier = email
		if flow == "sms" {
			identifier = uniquePhone()
		}
		invite, err := f.service.Backend().CreateAccountInvite(ctx, iam.UserActor(inviter), iam.NewAccountInvite{Email: email})
		require.NoError(t, err)
		var failed flowResponse
		if flow == "oidc" || flow == "oauth2" {
			provider := newSecurityTestProvider(t, f.service, flow == "oidc")
			f.mount()
			verified := true
			failed, _ = f.providerLogin(provider, providerTestIdentity{Subject: "rollback-" + uniqueSuffix(), Email: email, Verified: &verified}, invite.Code, false)
		} else {
			path := "/register"
			body := map[string]any{"identifier": identifier, "account_invite_token": invite.Code}
			if flow == "passwordless" {
				path = "/passwordless/start"
				body["mode"] = "both"
			} else {
				body["username"] = "roll" + uniqueSuffix()
				body["password"] = "Correct-horse-battery-1"
			}
			f.expect(202, f.post(path, body))
			confirm := "/verify/confirm"
			if flow == "passwordless" {
				confirm = "/passwordless/confirm"
			}
			failed = f.post(confirm, map[string]any{"identifier": identifier, "code": f.verifyCode(flow == "sms")})
		}
		require.GreaterOrEqual(t, failed.status, 400, flow+failed.raw)
		var exists, consumed bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 OR phone_number=$2),(SELECT consumed_at IS NOT NULL FROM account_registration_invites WHERE id=$3::uuid)`, email, identifier, invite.ID).Scan(&exists, &consumed))
		require.False(t, exists, flow)
		require.False(t, consumed, flow)
	}
}

func testProofLifecycle(f *accountFlow) {
	t, pool, ctx := f.t, fixtureBackend(f.service.Backend()).pg, f.t.Context()
	for _, phone := range []bool{false, true} {
		for _, passwordless := range []bool{false, true} {
			identifier := uniqueEmail("lifecycle")
			user, err := fixtureBackend(f.service.Backend()).createUser(ctx, identifier, "life"+uniqueSuffix())
			require.NoError(t, err)
			if phone {
				identifier = uniquePhone()
				_, err = pool.Exec(ctx, `UPDATE users SET phone_number=$1,phone_verified=false WHERE id=$2::uuid`, identifier, user.ID)
				require.NoError(t, err)
			}
			start, confirm, path, channel, amr := "/verify/request", "/verify/confirm", "/verify", "email", "email"
			if phone {
				channel, amr = "phone", "sms"
			}
			if passwordless {
				start, confirm, path, channel = "/passwordless/start", "/passwordless/confirm", "/login/link", amr
			}
			begin := func() {
				body := map[string]any{"identifier": identifier}
				if passwordless {
					body["mode"] = "both"
					body["return_to"] = "https://evil.example/steal"
				}
				f.expect(202, f.post(start, body))
			}
			begin()
			stale := f.verifyCode(phone)
			oldLink := f.deliveredLink(f.verifyURL(phone), path, channel)
			begin()
			link := f.deliveredLink(f.verifyURL(phone), path, channel)
			require.NotEqual(t, oldLink, link)
			otherConfirm := "/passwordless/confirm"
			if passwordless {
				otherConfirm = "/verify/confirm"
			}
			f.expect(400, f.post(otherConfirm, map[string]any{"token": link}))
			f.expect(400, f.post(confirm, map[string]any{"token": oldLink}))
			f.expect(401, f.post(confirm, map[string]any{"identifier": identifier, "code": stale}))
			// Guess budget survives reissue; four misses remain live, the fifth burns
			// both the code and its alternate link representation.
			for i := 0; i < 3; i++ {
				f.expect(401, f.post(confirm, map[string]any{"identifier": identifier, "code": "WRONG"}))
			}
			begin()
			link = f.deliveredLink(f.verifyURL(phone), path, channel)
			f.expect(401, f.post(confirm, map[string]any{"identifier": identifier, "code": "WRONG"}))
			f.expect(400, f.post(confirm, map[string]any{"token": link}))
			begin()
			current := f.verifyCode(phone)
			link = f.deliveredLink(f.verifyURL(phone), path, channel)
			done := f.expect(200, f.post(confirm, map[string]any{"identifier": identifier, "code": current}))
			tokens := done.TokenSet
			if passwordless {
				tokens = done.Tokens
				require.Empty(t, done.ReturnTo)
			}
			f.session(tokens, amr)
			f.expect(400, f.post(confirm, map[string]any{"token": link}))
			// The reverse order (link then code) has the same canonical winner. Existing
			// accounts remain available in InviteOnly mode without spending another invite.
			if passwordless {
				begin()
				current = f.verifyCode(phone)
				link = f.deliveredLink(f.verifyURL(phone), path, channel)
				done = f.expect(200, f.post(confirm, map[string]any{"token": link}))
				f.session(done.Tokens, amr)
				f.expect(401, f.post(confirm, map[string]any{"identifier": identifier, "code": current}))
			}
		}
	}
	// Completion paused on the account lock must not delete a newer issuance.
	email := uniqueEmail("reissue")
	user, err := fixtureBackend(f.service.Backend()).createUser(ctx, email, "reissue"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(f.service.Backend()).markEmailVerified(ctx, user.ID))
	begin := func() {
		f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "both"}))
	}
	begin()
	old := sentCode(t, f.email, testoutbox.Verification)
	lock, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer lock.Rollback(ctx)
	_, err = lock.Exec(ctx, `SELECT id FROM users WHERE id=$1::uuid FOR UPDATE`, user.ID)
	require.NoError(t, err)
	completed := make(chan flowResponse, 1)
	go func() { completed <- f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": old}) }()
	require.Eventually(t, func() bool {
		var n int
		err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%UserCredentialVersionForUpdate%'`).Scan(&n)
		return err == nil && n == 1
	}, 5*time.Second, 10*time.Millisecond)
	begin()
	newCode := sentCode(t, f.email, testoutbox.Verification)
	require.NoError(t, lock.Commit(ctx))
	f.expect(200, <-completed)
	f.expect(200, f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": newCode}))
}
