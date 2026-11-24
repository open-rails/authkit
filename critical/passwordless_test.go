package critical_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// codeProof is a delivered code with the challenge its start answered.
type codeProof struct {
	authtest.Message
	Challenge string
}

// challengeOf is the challenge a start's 202 answered.
func challengeOf(t *testing.T, r response) string {
	t.Helper()
	r.want(t, http.StatusAccepted, "")
	var out struct {
		Challenge string `json:"challenge"`
	}
	decode(t, r.body, &out)
	if out.Challenge == "" {
		t.Fatalf("start answered no challenge: %s", r.body)
	}
	return out.Challenge
}

func (f *fixture) passwordlessProof(t *testing.T, address, mode string) codeProof {
	t.Helper()
	challenge := challengeOf(t, f.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": address, "mode": mode}))
	return codeProof{f.out.Last(t, iam.MessageVerification, address), challenge}
}

// confirmCode confirms proof's code at path with its challenge.
func (f *fixture) confirmCode(t *testing.T, path, credential string, proof codeProof) response {
	t.Helper()
	return f.call(t, "POST", path, credential, map[string]string{"challenge": proof.Challenge, "code": proof.Code})
}

// behindProxy makes requests' X-Forwarded-For their client address and
// restores the default limits of buckets, which authtest lifts.
func behindProxy(buckets map[string]authkit.RateLimit) authtest.Option {
	return authtest.WithConfig(func(c *authkit.Config) {
		c.HTTP.DirectPeerIP = false
		c.HTTP.TrustedProxies = []string{"127.0.0.0/8"}
		maps.Copy(c.HTTP.RateLimits, buckets)
	})
}

// from posts body to path from client address.
func (f *fixture) from(t *testing.T, address, path string, body any) response {
	t.Helper()
	r, err := f.requestHeaders(t.Context(), "POST", path, "", body, http.Header{"X-Forwarded-For": {address}})
	noError(t, err)
	return r
}

// wrongCode is a six-digit code none of the messages to address carries.
func (f *fixture) wrongCode(t *testing.T, address string) string {
	t.Helper()
	sent := map[string]bool{}
	for _, m := range f.out.Messages(iam.MessageVerification, address) {
		sent[m.Code] = true
	}
	for n := 0; ; n++ {
		if code := fmt.Sprintf("%06d", n); !sent[code] {
			return code
		}
	}
}

func TestCriticalPasswordless(t *testing.T) {
	t.Run("AK-J33-C01_existing_email_and_SMS_codes_and_links_sign_in_the_owner", func(t *testing.T) {
		f := newFixture(t)
		email := f.user(t)
		phone, err := f.auth.CreateUser(t.Context(), iam.NewUser{Phone: "+12025550186", PhoneVerified: true, Username: "passwordlessphone"})
		noError(t, err)
		for _, account := range []struct{ address, id string }{{email.Email, email.ID}, {"+12025550186", phone.ID}} {
			for _, mode := range []string{"code", "link"} {
				t.Run(account.address+"/"+mode, func(t *testing.T) {
					proof := f.passwordlessProof(t, account.address, mode)
					body := map[string]string{"identifier": account.address}
					if mode == "code" {
						if proof.Code == "" {
							t.Fatal("code delivery missing")
						}
						body["challenge"], body["code"] = proof.Challenge, proof.Code
					} else {
						if proof.Token == "" {
							t.Fatal("link delivery missing")
						}
						body["token"] = proof.Token
					}
					tokensFrom(t, f.call(t, "POST", "/passwordless/confirm", "", body), account.id)
				})
			}
		}
	})
	t.Run("AK-J33-C02_new_accounts_still_obey_invitation_and_agreement_policy", func(t *testing.T) {
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.Agreements = []authkit.AgreementConfig{{Key: "terms", Version: "v1", URL: "https://policy.example/terms"}}
			c.Registration.Agreements = []string{"terms"}
			c.Registration.PasswordlessAutoRegistration = true
			c.Username.RandomNames = []string{"journeyperson"}
		}))
		proof := f.passwordlessProof(t, "agreement-signup@example.com", "code")
		f.confirmCode(t, "/passwordless/confirm", "", proof).want(t, http.StatusConflict, "agreement_required")
		_, err := f.auth.User(t.Context(), iam.UserByEmail(proof.To))
		if !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatal("missing consent created an account")
		}
		r := f.call(t, "POST", "/passwordless/confirm", "", map[string]any{"challenge": proof.Challenge, "code": proof.Code, "agreements": []iam.AgreementRef{{Key: "terms", Version: "v1"}}})
		r.want(t, http.StatusOK, "")
		var result signInResult
		decode(t, r.body, &result)
		if result.Status != "complete" || result.User == nil || result.Tokens == nil {
			t.Fatal("valid proof was consumed by the earlier consent refusal")
		}
		accepted, err := f.auth.UserAgreements(t.Context(), result.User.ID)
		noError(t, err)
		if len(accepted) != 1 || accepted[0].Key != "terms" || accepted[0].Version != "v1" {
			t.Fatal("signup failed to record its literal accepted document")
		}
		closed := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.Registration.NativeUserMode = iam.RegistrationModeInviteOnly
			c.Registration.PasswordlessAutoRegistration = true
		}))
		closed.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": "not-invited@example.com", "mode": "code"}).want(t, http.StatusForbidden, "registration_disabled")
		if len(closed.out.Messages(iam.MessageVerification, "not-invited@example.com")) != 0 {
			t.Fatal("invite-only refusal delivered a signup proof")
		}
	})
	t.Run("AK-J33-C03_parallel_and_lost_response_replay_have_one_winner", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		proof := f.passwordlessProof(t, u.Email, "code")
		body := map[string]string{"challenge": proof.Challenge, "code": proof.Code}
		answers := make([]response, 2)
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range answers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				answers[i], errs[i] = f.request(t.Context(), "POST", "/passwordless/confirm", "", body)
			}()
		}
		close(start)
		wg.Wait()
		success := 0
		for i, r := range answers {
			noError(t, errs[i])
			if r.status == http.StatusOK {
				success++
				tokensFrom(t, r, u.ID)
			} else {
				r.want(t, http.StatusUnauthorized, "invalid_code")
			}
		}
		if success != 1 {
			t.Fatalf("one proof issued%d sessions", success)
		}
		f.call(t, "POST", "/passwordless/confirm", "", body).want(t, http.StatusUnauthorized, "invalid_code")
		sessions, err := f.auth.Sessions(t.Context(), u.ID)
		noError(t, err)
		if len(sessions) != 1 {
			t.Fatal("proof replay forked session authority")
		}
	})
	t.Run("AK-J33-C04_proof_cannot_cross_account_tenant_purpose_or_expiry", func(t *testing.T) {
		f := newFixture(t, multiTenant)
		u := f.user(t)
		other := f.user(t)
		proof := f.passwordlessProof(t, u.Email, "code")
		f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"identifier": other.Email, "challenge": proof.Challenge, "code": proof.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		otherProof := f.passwordlessProof(t, other.Email, "code")
		f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"challenge": otherProof.Challenge, "code": proof.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		id := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: id, Slug: "passwordless-other"}))
		view, err := f.auth.ForTenant(t.Context(), id)
		noError(t, err)
		server := httptest.NewServer(view.Handler())
		t.Cleanup(server.Close)
		g := &fixture{auth: view, server: server}
		g.confirmCode(t, "/passwordless/confirm", "", proof).want(t, http.StatusUnauthorized, "invalid_code")
		tokensFrom(t, f.confirmCode(t, "/passwordless/confirm", "", proof), u.ID)
		reset := f.resetProof(t, u.Email)
		f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"token": reset}).want(t, http.StatusBadRequest, "invalid_link")
		expired := f.passwordlessProof(t, u.Email, "code")
		f.expireProofs(t)
		f.confirmCode(t, "/passwordless/confirm", "", expired).want(t, http.StatusUnauthorized, "invalid_code")
	})
	t.Run("AK-J33-C05_pending_proof_cannot_survive_account_or_credential_retirement", func(t *testing.T) {
		for _, change := range []string{"ban", "delete", "password"} {
			t.Run(change, func(t *testing.T) {
				f := newFixture(t)
				u := f.user(t)
				proof := f.passwordlessProof(t, u.Email, "code")
				switch change {
				case "ban":
					noError(t, f.auth.Ban(t.Context(), iam.SystemIdentity(), u.ID, iam.Ban{}))
				case "delete":
					noError(t, f.auth.Start(context.Background()))
					rows, err := f.auth.DeleteUsers(t.Context(), iam.SystemIdentity(), []string{u.ID})
					noError(t, err)
					if len(rows) != 1 || rows[0].Err != nil {
						t.Fatalf("delete:%+v", rows)
					}
				case "password":
					token := f.resetProof(t, u.Email)
					f.call(t, "POST", "/password/reset/confirm", "", map[string]string{"token": token, "new_password": "Passwordless-retirement-7"}).want(t, http.StatusNoContent, "")
				}
				code := "invalid_code"
				if change == "ban" {
					code = "user_banned"
				}
				f.confirmCode(t, "/passwordless/confirm", "", proof).want(t, http.StatusUnauthorized, code)
				sessions, err := f.auth.Sessions(t.Context(), u.ID)
				if change == "delete" {
					if err == nil && len(sessions) != 0 {
						t.Fatal("retired account obtained a session")
					}
				} else {
					noError(t, err)
					if len(sessions) != 0 {
						t.Fatal("retired proof obtained a session")
					}
				}
			})
		}
	})
	t.Run("AK-J33-C06_contact_proof_still_requires_an_independent_second_factor", func(t *testing.T) {
		f := mfaFixture(t, iam.TwoFactorOptional)
		u := f.user(t)
		secret, created := f.totp(t, f.signIn(t, u).AccessToken)
		proof := f.passwordlessProof(t, u.Email, "code")
		r := f.confirmCode(t, "/passwordless/confirm", "", proof)
		r.want(t, http.StatusOK, "")
		var result struct {
			Status string         `json:"status"`
			Tokens *iam.TokenSet  `json:"token_set"`
			Step   loginChallenge `json:"second_factor"`
		}
		decode(t, r.body, &result)
		if result.Status != "second_factor_required" || result.Tokens != nil || result.Step.UserID != u.ID {
			t.Fatal("contact proof bypassed the independent factor")
		}
		tokensFrom(t, f.call(t, "POST", "/2fa/verify", "", map[string]string{"user_id": u.ID, "challenge": result.Step.Challenge, "factor_id": created.Factor.ID, "code": authtest.TOTPCode(t, secret, time.Now().Add(30*time.Second))}), u.ID)
	})
	t.Run("AK-J33-C07_one_address_cannot_lock_another_account_out_of_code_sign_in", func(t *testing.T) {
		defaults := authkit.DefaultRateLimits()
		start, confirm := defaults["passwordless_start"], defaults["passwordless_confirm"]
		// No cooldown, so one address spends its whole start budget now.
		start.Cooldown = 0
		f := newFixture(t, behindProxy(map[string]authkit.RateLimit{
			"passwordless_start": start, "passwordless_confirm": confirm,
			"passwordless_start_identifier": defaults["passwordless_start_identifier"],
		}))
		victim := f.user(t)
		before := len(f.out.Messages(iam.MessageVerification, victim.Email))
		const attacker, owner = "192.0.2.10", "198.51.100.20"
		body := map[string]string{"identifier": victim.Email, "mode": "code"}
		var spent []string
		for range start.Limit {
			spent = append(spent, challengeOf(t, f.from(t, attacker, "/passwordless/start", body)))
		}
		f.from(t, attacker, "/passwordless/start", body).want(t, http.StatusTooManyRequests, "rate_limited")
		// Wrong codes naming the victim's address, five per challenge, until
		// the attacker's confirm budget is spent.
		wrong := f.wrongCode(t, victim.Email)
		for i := range confirm.Limit {
			f.from(t, attacker, "/passwordless/confirm", map[string]string{"identifier": victim.Email, "challenge": spent[i/maxFailures], "code": wrong}).want(t, http.StatusUnauthorized, "invalid_code")
		}
		f.from(t, attacker, "/passwordless/confirm", map[string]string{"challenge": spent[0], "code": wrong}).want(t, http.StatusTooManyRequests, "rate_limited")
		// The victim, from its own address, is sent a code and signs in with it.
		proof := codeProof{Challenge: challengeOf(t, f.from(t, owner, "/passwordless/start", body))}
		if got := len(f.out.Messages(iam.MessageVerification, victim.Email)) - before; got != start.Limit+1 {
			t.Fatalf("%d codes reached the victim, want %d", got, start.Limit+1)
		}
		proof.Message = f.out.Last(t, iam.MessageVerification, victim.Email)
		tokensFrom(t, f.from(t, owner, "/passwordless/confirm", map[string]string{"challenge": proof.Challenge, "code": proof.Code}), victim.ID)
	})
	t.Run("AK-J33-C08_a_code_answers_only_its_own_challenge_and_burns_only_it", func(t *testing.T) {
		f := newFixture(t)
		u := f.user(t)
		first := f.passwordlessProof(t, u.Email, "code")
		second := f.passwordlessProof(t, u.Email, "code")
		third := f.passwordlessProof(t, u.Email, "code")
		// A later start replaces no earlier one.
		tokensFrom(t, f.confirmCode(t, "/passwordless/confirm", "", first), u.ID)
		if second.Code != third.Code {
			f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"challenge": third.Challenge, "code": second.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		}
		wrong := f.wrongCode(t, u.Email)
		for range maxFailures {
			f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"challenge": second.Challenge, "code": wrong}).want(t, http.StatusUnauthorized, "invalid_code")
		}
		f.confirmCode(t, "/passwordless/confirm", "", second).want(t, http.StatusUnauthorized, "invalid_code")
		tokensFrom(t, f.confirmCode(t, "/passwordless/confirm", "", third), u.ID)
	})
	t.Run("AK-J33-C09_past_the_destination_quota_a_start_answers_alike_and_sends_nothing", func(t *testing.T) {
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.HTTP.RateLimits["passwordless_start_identifier"] = authkit.RateLimit{Limit: 1, Window: time.Hour}
		}))
		u := f.user(t)
		first := f.passwordlessProof(t, u.Email, "code")
		over := challengeOf(t, f.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": u.Email, "mode": "code"}))
		missing := challengeOf(t, f.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": "nobody-here@example.com", "mode": "code"}))
		if len(over) != len(first.Challenge) || len(missing) != len(first.Challenge) {
			t.Fatal("a withheld or empty start answered differently")
		}
		if got := len(f.out.Messages(iam.MessageVerification, u.Email)); got != 1 {
			t.Fatalf("a start past the quota sent: %d codes", got)
		}
		f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"challenge": over, "code": first.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		tokensFrom(t, f.confirmCode(t, "/passwordless/confirm", "", first), u.ID)

		// A number past its text-message quota answers alike too.
		g := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.HTTP.RateLimits["sms_number"] = authkit.RateLimit{Limit: 1, Window: time.Hour}
		}))
		const phone = "+12025550187"
		p, err := g.auth.CreateUser(t.Context(), iam.NewUser{Phone: phone, PhoneVerified: true, Username: "smsquotaowner"})
		noError(t, err)
		sent := g.passwordlessProof(t, phone, "code")
		withheld := challengeOf(t, g.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": phone, "mode": "code"}))
		if got := len(g.out.Messages(iam.MessageVerification, phone)); got != 1 {
			t.Fatalf("a text past its number's quota sent: %d codes", got)
		}
		g.call(t, "POST", "/passwordless/confirm", "", map[string]string{"challenge": withheld, "code": sent.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		tokensFrom(t, g.confirmCode(t, "/passwordless/confirm", "", sent), p.ID)
	})
}

// maxFailures is how many wrong codes burn a challenge.
const maxFailures = 5
