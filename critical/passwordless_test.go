package critical_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

func (f *fixture) passwordlessProof(t *testing.T, address, mode string) authtest.Message {
	t.Helper()
	f.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": address, "mode": mode}).want(t, http.StatusAccepted, "")
	return f.out.Last(t, iam.MessageVerification, address)
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
						body["code"] = proof.Code
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
		f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"identifier": proof.To, "code": proof.Code}).want(t, http.StatusConflict, "agreement_required")
		_, err := f.auth.User(t.Context(), iam.UserByEmail(proof.To))
		if !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatal("missing consent created an account")
		}
		r := f.call(t, "POST", "/passwordless/confirm", "", map[string]any{"identifier": proof.To, "code": proof.Code, "agreements": []iam.AgreementRef{{Key: "terms", Version: "v1"}}})
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
		body := map[string]string{"identifier": u.Email, "code": proof.Code}
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
		f := newFixture(t)
		u := f.user(t)
		other := f.user(t)
		proof := f.passwordlessProof(t, u.Email, "code")
		f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"identifier": other.Email, "code": proof.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		id := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		view, err := f.auth.ForTenant(t.Context(), id)
		noError(t, err)
		server := httptest.NewServer(view.Handler())
		t.Cleanup(server.Close)
		g := &fixture{auth: view, server: server}
		g.call(t, "POST", "/passwordless/confirm", "", map[string]string{"identifier": u.Email, "code": proof.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		tokensFrom(t, f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"identifier": u.Email, "code": proof.Code}), u.ID)
		reset := f.resetProof(t, u.Email)
		f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"token": reset}).want(t, http.StatusBadRequest, "invalid_link")
		expired := f.passwordlessProof(t, u.Email, "code")
		f.expireProofs(t)
		f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"identifier": u.Email, "code": expired.Code}).want(t, http.StatusUnauthorized, "invalid_code")
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
				f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"identifier": u.Email, "code": proof.Code}).want(t, http.StatusUnauthorized, code)
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
		r := f.call(t, "POST", "/passwordless/confirm", "", map[string]string{"identifier": u.Email, "code": proof.Code})
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
}
