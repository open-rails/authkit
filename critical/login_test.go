package critical_test

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/password"
)

func TestCriticalPasswordAdmission(t *testing.T) {
	f := newFixture(t)
	t.Run("AK-J04-C01_valid_and_invalid_password_admission", func(t *testing.T) {
		u := f.user(t)
		for _, address := range []string{u.Email, "missing-person@example.com"} {
			f.call(t, "POST", "/password/login", "", map[string]string{"identifier": address, "password": "wrong-password"}).want(t, http.StatusUnauthorized, "invalid_credentials")
		}
		live, err := f.auth.Sessions(t.Context(), u.ID)
		noError(t, err)
		if len(live) != 0 {
			t.Fatal("invalid password created a session")
		}
		f.signIn(t, u)
	})
	t.Run("AK-J04-C02_disabled_unverified_and_MFA_required_accounts_do_not_get_ordinary_sessions", func(t *testing.T) {
		u := f.user(t)
		noError(t, f.auth.Ban(t.Context(), iam.SystemIdentity(), u.ID, iam.Ban{}))
		f.call(t, "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}).want(t, http.StatusUnauthorized, "user_banned")
		g := newFixture(t)
		noError(t, g.auth.Start(context.Background()))
		deleted := g.user(t)
		results, err := g.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{deleted.ID})
		noError(t, err)
		if len(results) != 1 || results[0].Err != nil {
			t.Fatalf("delete: %+v", results)
		}
		g.call(t, "POST", "/password/login", "", map[string]string{"identifier": deleted.Email, "password": deleted.Password}).want(t, http.StatusUnauthorized, "account_disabled")
		// A host-created account signs in unproven, and stays unproven.
		unverified, err := g.auth.CreateUser(t.Context(), iam.NewUser{Email: "unverified-login@example.com", Username: "unverifiedlogin", Password: authtest.Password})
		noError(t, err)
		r := g.call(t, "POST", "/password/login", "", map[string]string{"identifier": *unverified.Email, "password": authtest.Password})
		tokensFrom(t, r, unverified.ID)
		if still, err := g.auth.User(t.Context(), iam.UserByID(unverified.ID)); err != nil || still.EmailVerified {
			t.Fatalf("an unproven sign-in proved the address: %v", err)
		}
		var pending signInResult
		m := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.TwoFactor = iam.TwoFactorRequired
		}))
		required := m.user(t)
		r = m.call(t, "POST", "/password/login", "", map[string]string{"identifier": required.Email, "password": required.Password})
		r.want(t, http.StatusOK, "")
		decode(t, r.body, &pending)
		if pending.Status != "enrollment_required" || pending.Tokens != nil {
			t.Fatalf("required MFA issued an ordinary session: %s", r.body)
		}
	})
	t.Run("AK-J04-C03_new_device_limit_requires_the_delivered_code", func(t *testing.T) {
		g := deviceFixture(t)
		u := g.user(t)
		g.signIn(t, u)
		step, cookie := g.deviceStep(t, u)
		proof := g.out.Last(t, iam.MessageNewDeviceCode, u.Email)
		body := map[string]string{"user_id": u.ID, "challenge": step.Challenge, "code": proof.Code}
		r, err := g.requestHeaders(t.Context(), "POST", "/device-verification/confirm", "", body, http.Header{"Cookie": {cookie}})
		noError(t, err)
		tokensFrom(t, r, u.ID)
	})
	t.Run("AK-J04-C04_device_proof_cannot_move_accounts_expire_or_replay", func(t *testing.T) {
		g := deviceFixture(t)
		u := g.user(t)
		other := g.user(t)
		g.signIn(t, u)
		step, _ := g.deviceStep(t, u)
		proof := g.out.Last(t, iam.MessageNewDeviceCode, u.Email)
		g.call(t, "POST", "/device-verification/confirm", "", map[string]string{"user_id": other.ID, "challenge": step.Challenge, "code": proof.Code}).want(t, http.StatusUnauthorized, "invalid_challenge")
		wrong := "0" + proof.Code[1:]
		if wrong == proof.Code {
			wrong = "1" + proof.Code[1:]
		}
		g.call(t, "POST", "/device-verification/confirm", "", map[string]string{"user_id": u.ID, "challenge": step.Challenge, "code": wrong}).want(t, http.StatusUnauthorized, "invalid_code")
		body := map[string]string{"user_id": u.ID, "challenge": step.Challenge, "code": proof.Code}
		tokensFrom(t, g.call(t, "POST", "/device-verification/confirm", "", body), u.ID)
		g.call(t, "POST", "/device-verification/confirm", "", body).want(t, http.StatusUnauthorized, "invalid_challenge")
		another := g.user(t)
		g.signIn(t, another)
		expired, _ := g.deviceStep(t, another)
		code := g.out.Last(t, iam.MessageNewDeviceCode, another.Email).Code
		g.expireProofs(t)
		g.call(t, "POST", "/device-verification/confirm", "", map[string]string{"user_id": another.ID, "challenge": expired.Challenge, "code": code}).want(t, http.StatusUnauthorized, "invalid_challenge")
	})
	t.Run("AK-J04-C05_IP_and_identifier_budgets_are_enforced", func(t *testing.T) {
		g := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			config.Tune(c, func(tn *config.Tuning) {
				tn.RateLimits["password_login"] = config.RateLimit{Limit: 1, Window: time.Hour}
			})
		}))
		g.call(t, "POST", "/password/login", "", map[string]string{"identifier": "first@example.com", "password": "bad-password"}).want(t, http.StatusUnauthorized, "invalid_credentials")
		r := g.call(t, "POST", "/password/login", "", map[string]string{"identifier": "different@example.com", "password": "bad-password"})
		r.want(t, http.StatusTooManyRequests, "rate_limited")
		if r.header.Get("Retry-After") == "" {
			t.Fatal("rate refusal omitted Retry-After")
		}
		// The public registration send has an additional quota per address
		// it sends to; trusted distinct source addresses must not buy
		// unlimited email sends. Past it the sign-up answers as one does and
		// sends nothing.
		h := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.HTTP.DirectPeerIP = false
			c.HTTP.TrustedProxies = []string{"127.0.0.0/8"}
			config.Tune(c, func(tn *config.Tuning) {
				tn.RateLimits["register_create_identifier"] = config.RateLimit{Limit: 1, Window: time.Hour}
			})
		}))
		body := map[string]string{"identifier": "budgeted@example.com", "username": "budgetedperson", "password": authtest.Password}
		a, err := h.requestHeaders(t.Context(), "POST", "/register", "", body, http.Header{"X-Forwarded-For": {"192.0.2.10"}})
		noError(t, err)
		challengeOf(t, a)
		body = map[string]string{"identifier": "budgeted@example.com", "username": "budgetedother", "password": authtest.Password}
		h.call(t, "POST", "/register/abandon", "", map[string]string{"identifier": "budgeted@example.com", "password": authtest.Password}).want(t, http.StatusNoContent, "")
		b, err := h.requestHeaders(t.Context(), "POST", "/register", "", body, http.Header{"X-Forwarded-For": {"192.0.2.11"}})
		noError(t, err)
		challengeOf(t, b)
		if len(h.out.Messages(iam.MessageVerification, "budgeted@example.com")) != 1 {
			t.Fatal("identifier budget allowed duplicate external delivery")
		}
	})
	t.Run("AK-J04-C07_identifier_budget_spans_addresses_and_treats_missing_accounts_alike", func(t *testing.T) {
		for _, store := range []struct {
			name string
			deps []authtest.Option
		}{
			{"memory", nil},
			{"redis", []authtest.Option{authtest.WithDeps(func(d *authkit.Deps) { d.Redis = realRedis(t) })}},
		} {
			t.Run(store.name, func(t *testing.T) {
				g := newFixture(t, append([]authtest.Option{authtest.WithConfig(func(c *authkit.Config) {
					c.HTTP.DirectPeerIP = false
					c.HTTP.TrustedProxies = []string{"127.0.0.0/8"}
					config.Tune(c, func(tn *config.Tuning) {
						tn.RateLimits["password_login_identifier"] = config.RateLimit{Limit: 2, Window: time.Hour}
					})
				})}, store.deps...)...)
				u, other, taken := g.user(t), g.user(t), g.user(t)
				phone, err := g.auth.CreateUser(t.Context(), iam.NewUser{Phone: "+12025550179", PhoneVerified: true, Username: "budgetphone", Password: authtest.Password})
				noError(t, err)
				// Each request comes from a new /64, so only the identifier budget can refuse it.
				addresses := 0
				login := func(identifier, password string) response {
					addresses++
					r, err := g.requestHeaders(t.Context(), "POST", "/password/login", "", map[string]string{"identifier": identifier, "password": password},
						http.Header{"X-Forwarded-For": {fmt.Sprintf("2001:db8:%x::1", addresses)}})
					noError(t, err)
					return r
				}
				want := map[string]any{"action": "password_login_identifier", "allowed": false, "reason": "limit_exceeded", "limit": 2.0, "remaining": 0.0, "window_seconds": 3600.0, "cooldown_seconds": nil}
				refused := func(r response) {
					t.Helper()
					r.want(t, http.StatusTooManyRequests, "rate_limited")
					if r.header.Get("Retry-After") == "" {
						t.Fatal("identifier refusal omitted Retry-After")
					}
					var env iam.ErrorEnvelope
					decode(t, r.body, &env)
					delete(env.Error.Metadata, "retry_after_seconds")
					delete(env.Error.Metadata, "next_allowed_at")
					if !reflect.DeepEqual(env.Error.Metadata, want) {
						t.Fatalf("identifier refusal = %v, want %v", env.Error.Metadata, want)
					}
				}

				// Every kind of identifier, in any spelling, with or without an account:
				// right passwords spend nothing, and the third wrong one is refused alike.
				for _, c := range []struct{ first, second, probe, password string }{
					{u.Email, strings.ToUpper(u.Email), " " + u.Email + " ", u.Password},
					{u.Username, strings.ToUpper(u.Username), u.Username, u.Password},
					{*phone.Phone, *phone.Phone, " " + *phone.Phone, authtest.Password},
					{"missing-person@example.com", "MISSING-PERSON@EXAMPLE.COM", "missing-person@example.com", ""},
					{"missingperson", "MissingPerson", "missingperson", ""},
					{"+12025550180", "+12025550180", "+12025550180", ""},
				} {
					if c.password != "" {
						login(c.first, c.password).want(t, http.StatusOK, "")
						login(c.second, c.password).want(t, http.StatusOK, "")
					}
					login(c.first, "wrong-password").want(t, http.StatusUnauthorized, "invalid_credentials")
					login(c.second, "wrong-password").want(t, http.StatusUnauthorized, "invalid_credentials")
					refused(login(c.probe, "wrong-password"))
					if c.password != "" {
						refused(login(c.first, c.password))
					}
				}

				// A pending sign-up's password proves no account, so signing in with it
				// counts, whether or not an account holds the address.
				const pending = "Pending-guess-password-6"
				for i, address := range []string{taken.Email, "pending-person@example.com"} {
					g.call(t, "POST", "/register", "", map[string]string{"identifier": address, "username": fmt.Sprintf("pendingguess%d", i), "password": pending}).want(t, http.StatusAccepted, "")
					for range 2 {
						r := login(address, pending)
						r.want(t, http.StatusOK, "")
						var out signInResult
						decode(t, r.body, &out)
						if out.Status != "verification_required" || out.Tokens != nil {
							t.Fatalf("pending password for %s answered %s", address, r.body)
						}
					}
					refused(login(address, pending))
				}

				// While the email is refused, a reset works but does not lift it, a code
				// still signs in, and another account keeps its own budget.
				const changed = "Budget-reset-password-5"
				g.call(t, "POST", "/password/reset/confirm", "", map[string]string{"token": g.resetProof(t, u.Email), "new_password": changed}).want(t, http.StatusNoContent, "")
				refused(login(u.Email, changed))
				tokensFrom(t, g.confirmCode(t, "/passwordless/confirm", "", g.passwordlessProof(t, u.Email, "code")), u.ID)
				tokensFrom(t, login(other.Email, other.Password), other.ID)

				// A spent budget frees itself as its window passes.
				h := newFixture(t, append([]authtest.Option{authtest.WithConfig(func(c *authkit.Config) {
					config.Tune(c, func(tn *config.Tuning) {
						tn.RateLimits["password_login_identifier"] = config.RateLimit{Limit: 1, Window: 5 * time.Second}
					})
				})}, store.deps...)...)
				v := h.user(t)
				h.call(t, "POST", "/password/login", "", map[string]string{"identifier": v.Email, "password": "wrong-password"}).want(t, http.StatusUnauthorized, "invalid_credentials")
				h.call(t, "POST", "/password/login", "", map[string]string{"identifier": v.Email, "password": v.Password}).want(t, http.StatusTooManyRequests, "rate_limited")
				var r response
				eventually(t, "the spent identifier budget to recover", func() bool {
					r = h.call(t, "POST", "/password/login", "", map[string]string{"identifier": v.Email, "password": v.Password})
					return r.status != http.StatusTooManyRequests
				})
				tokensFrom(t, r, v.ID)
			})
		}
	})
	t.Run("AK-J04-C08_account_state_shows_only_after_the_password_is_proved", func(t *testing.T) {
		g := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			config.Tune(c, func(tn *config.Tuning) {
				tn.RateLimits["password_login"] = config.RateLimit{Limit: 1000, Window: time.Hour}
			})
		}))
		banned, err := g.auth.CreateUser(t.Context(), iam.NewUser{Email: "banned-state@example.com", Phone: "+12025550181", Username: "bannedstate", Password: authtest.Password, EmailVerified: true, PhoneVerified: true})
		noError(t, err)
		noPassword, err := g.auth.CreateUser(t.Context(), iam.NewUser{Email: "no-password-state@example.com", Phone: "+12025550182", Username: "nopasswordstate", EmailVerified: true, PhoneVerified: true})
		noError(t, err)
		unproven, err := g.auth.CreateUser(t.Context(), iam.NewUser{Email: "unproven-state@example.com", Username: "unprovenstate"})
		noError(t, err)
		for _, u := range []iam.User{banned, noPassword} {
			noError(t, g.auth.Ban(t.Context(), iam.SystemIdentity(), u.ID, iam.Ban{}))
		}
		login := func(identifier, password string) response {
			return g.call(t, "POST", "/password/login", "", map[string]string{"identifier": identifier, "password": password})
		}
		for _, identifier := range []string{*banned.Email, banned.Username, *banned.Phone, *noPassword.Email, noPassword.Username, *noPassword.Phone, *unproven.Email, unproven.Username} {
			login(identifier, "wrong-password").want(t, http.StatusUnauthorized, "invalid_credentials")
		}
		for _, identifier := range []string{*banned.Email, banned.Username, *banned.Phone} {
			login(identifier, authtest.Password).want(t, http.StatusUnauthorized, "user_banned")
		}
		// A refusal that skips the password check answers many times sooner than a missing account.
		identifiers := []string{"missing-state@example.com", *banned.Email, *noPassword.Email, *unproven.Email}
		fastest := map[string]time.Duration{}
		for range 5 {
			for _, identifier := range identifiers {
				start := time.Now()
				login(identifier, "wrong-password").want(t, http.StatusUnauthorized, "invalid_credentials")
				if took := time.Since(start); fastest[identifier] == 0 || took < fastest[identifier] {
					fastest[identifier] = took
				}
			}
		}
		for _, identifier := range identifiers[1:] {
			if fastest[identifier] < fastest[identifiers[0]]/4 {
				t.Fatalf("wrong password for %s answered in %s, for a missing account in %s", identifier, fastest[identifier], fastest[identifiers[0]])
			}
		}
	})
	t.Run("AK-J04-C09_missing_account_costs_a_password_check_after_the_hash_budget_was_full", func(t *testing.T) {
		// A cached dummy hash fails this only as the process's first missing-account sign-in: run it alone to prove that.
		g := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			config.Tune(c, func(tn *config.Tuning) {
				tn.RateLimits["password_login"] = config.RateLimit{Limit: 100000, Window: time.Hour}
			})
		}))
		u := g.user(t)
		// Ten times the default cost, so a few rounds of these keep the budget full past its one-second wait.
		slow := &iam.PasswordHash{Hash: "$argon2id$v=19$m=65536,t=10,p=1$" + strings.Repeat("A", 22) + "$" + strings.Repeat("A", 43), Algo: iam.HashArgon2id}
		rows := make([]iam.ImportUser, 12*max(2, runtime.GOMAXPROCS(0)))
		for i := range rows {
			rows[i] = iam.ImportUser{Username: fmt.Sprintf("slowhash%d", i), PasswordHash: slow}
		}
		result, err := g.auth.ImportUsers(t.Context(), rows, iam.ImportOptions{})
		noError(t, err)
		if result.Inserted != len(rows) {
			t.Fatalf("import result: %+v", result)
		}
		wrong := func(identifier string) (response, error) {
			return g.request(t.Context(), "POST", "/password/login", "", map[string]string{"identifier": identifier, "password": "wrong-password"})
		}
		var flood sync.WaitGroup
		var refused atomic.Int32
		for _, row := range rows {
			flood.Go(func() {
				if r, err := wrong(row.Username); err == nil && r.status == http.StatusServiceUnavailable {
					refused.Add(1)
				}
			})
		}
		time.Sleep(50 * time.Millisecond)
		r, err := wrong("missing-while-busy")
		noError(t, err)
		if r.status != http.StatusServiceUnavailable && r.status != http.StatusUnauthorized {
			t.Fatalf("missing account while busy: %d %s", r.status, r.body)
		}
		flood.Wait()
		if refused.Load() == 0 {
			t.Fatal("the flood never filled the hash budget")
		}
		identifiers := []string{u.Username, "missing-after-busy"}
		fastest := map[string]time.Duration{}
		for range 5 {
			for _, identifier := range identifiers {
				start := time.Now()
				r, err := wrong(identifier)
				noError(t, err)
				r.want(t, http.StatusUnauthorized, "invalid_credentials")
				if took := time.Since(start); fastest[identifier] == 0 || took < fastest[identifier] {
					fastest[identifier] = took
				}
			}
		}
		if fastest[identifiers[1]] < fastest[identifiers[0]]/4 {
			t.Fatalf("wrong password for a missing account answered in %s, for an account in %s", fastest[identifiers[1]], fastest[identifiers[0]])
		}
	})
}

func TestCriticalUnprovenPasswordSignIn(t *testing.T) {
	t.Run("required_MFA_still_applies", func(t *testing.T) {
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor = iam.TwoFactorRequired }))
		u, err := f.auth.CreateUser(t.Context(), iam.NewUser{Email: "unproven-mfa@example.com", Username: "unprovenmfa", Password: authtest.Password})
		noError(t, err)
		r := f.call(t, "POST", "/password/login", "", map[string]string{"identifier": *u.Email, "password": authtest.Password})
		r.want(t, http.StatusOK, "")
		var out signInResult
		decode(t, r.body, &out)
		if out.Status != "enrollment_required" || out.Tokens != nil {
			t.Fatalf("unproven password sign-in bypassed required MFA: %s", r.body)
		}
	})
	hash, err := password.HashArgon2id(t.Context(), authtest.Password)
	noError(t, err)
	// An imported account's contact is unproven: it signs in by password,
	// and stays unproven.
	for _, allow := range []bool{true} {
		t.Run("unproven_password_sign_in", func(t *testing.T) {
			f := newFixture(t)
			for _, imported := range []iam.ImportUser{
				{Email: "imported-login@example.com", Username: "importedemail"},
				{Phone: "+12025550178", Username: "importedphone"},
			} {
				t.Run(imported.Username, func(t *testing.T) {
					imported.PasswordHash = &iam.PasswordHash{Hash: hash, Algo: iam.HashArgon2id}
					result, err := f.auth.ImportUsers(t.Context(), []iam.ImportUser{imported}, iam.ImportOptions{})
					noError(t, err)
					if result.Inserted != 1 {
						t.Fatalf("import result: %+v", result)
					}
					u, err := f.auth.User(t.Context(), iam.UserByUsername(imported.Username))
					noError(t, err)
					identifier := imported.Email
					if identifier == "" {
						identifier = imported.Phone
					}
					f.call(t, "POST", "/password/login", "", map[string]string{"identifier": identifier, "password": "wrong-password"}).want(t, http.StatusUnauthorized, "invalid_credentials")
					live, err := f.auth.Sessions(t.Context(), u.ID)
					noError(t, err)
					if len(live) != 0 || len(f.out.Messages(iam.MessageVerification, identifier)) != 0 {
						t.Fatal("wrong password created a session or requested verification")
					}
					r := f.call(t, "POST", "/password/login", "", map[string]string{"identifier": identifier, "password": authtest.Password})
					if allow {
						tokens := tokensFrom(t, r, u.ID)
						f.call(t, "GET", "/me", tokens.AccessToken, nil).want(t, http.StatusOK, "")
						if len(f.out.Messages(iam.MessageVerification, identifier)) != 0 {
							t.Fatal("unproven password sign-in requested verification")
						}
					} else {
						r.want(t, http.StatusOK, "")
						var out signInResult
						decode(t, r.body, &out)
						if out.Status != "verification_required" || out.Tokens != nil {
							t.Fatalf("default sign-in skipped contact proof: %s", r.body)
						}
						f.out.Last(t, iam.MessageVerification, identifier)
					}
					u, err = f.auth.User(t.Context(), iam.UserByID(u.ID))
					noError(t, err)
					if u.EmailVerified || u.PhoneVerified {
						t.Fatal("password sign-in fabricated contact proof")
					}
				})
			}
		})
	}
}

type deviceStep struct {
	UserID    string `json:"user_id"`
	Challenge string `json:"challenge"`
}

func deviceFixture(t *testing.T) *fixture {
	return newFixture(t, authtest.WithConfig(func(c *authkit.Config) { config.Tune(c, func(tn *config.Tuning) { tn.NewDevicesPerAccount = 1 }) }))
}
func (f *fixture) deviceStep(t *testing.T, u authtest.User) (deviceStep, string) {
	t.Helper()
	// A cookieless native client is deliberately recognized by its address.
	// Obtain a fresh server-issued device cookie for a distinct browser, then
	// present it with this account's password. The cookie itself grants nothing.
	probe := f.call(t, "POST", "/password/login", "", map[string]string{"identifier": "new-browser-probe@example.com", "password": "invalid-password"})
	probe.want(t, http.StatusUnauthorized, "invalid_credentials")
	var sentCookies []string
	for _, cookie := range (&http.Response{Header: probe.header}).Cookies() {
		if cookie.Value != "" && cookie.MaxAge >= 0 {
			sentCookies = append(sentCookies, cookie.Name+"="+cookie.Value)
		}
	}
	cookie := strings.Join(sentCookies, "; ")
	if cookie == "" {
		t.Fatal("server did not issue the new device's opaque cookie")
	}
	r, err := f.requestHeaders(t.Context(), "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}, http.Header{"Cookie": {cookie}})
	noError(t, err)
	r.want(t, http.StatusOK, "")
	var result struct {
		Status string        `json:"status"`
		Tokens *iam.TokenSet `json:"token_set"`
		Step   deviceStep    `json:"device_verification"`
	}
	decode(t, r.body, &result)
	if result.Status != "device_verification_required" || result.Tokens != nil || result.Step.UserID != u.ID || result.Step.Challenge == "" {
		t.Fatalf("new-device proof was bypassed: %s", r.body)
	}
	return result.Step, cookie
}
