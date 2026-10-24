package critical_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

func proofRegistration() authtest.Option {
	return authtest.WithConfig(func(c *authkit.Config) { c.Registration.Verification = iam.RegistrationVerificationRequired })
}

func (f *fixture) register(t *testing.T, address, name string) response {
	t.Helper()
	return f.call(t, "POST", "/register", "", map[string]string{"identifier": address, "username": name, "password": authtest.Password})
}

// PostgreSQL owns ephemeral expiry. This changes only the clock input of
// proofs in this journey's isolated schema; all outcomes are observed through
// public requests, never by asserting an internal table representation.
func (f *fixture) expireProofs(t *testing.T) {
	t.Helper()
	_, err := f.pool.Exec(t.Context(), "UPDATE "+pgx.Identifier{f.schema, "ephemeral_kv"}.Sanitize()+" SET expires_at = statement_timestamp() - interval '1 second'")
	noError(t, err)
}

func TestCriticalRegistration(t *testing.T) {
	f := newFixture(t, proofRegistration())
	t.Run("AK-J03-C01_email_and_sms_require_delivered_proof", func(t *testing.T) {
		for i, address := range []string{"signup-person@example.com", "+12025550123"} {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				f.register(t, address, fmt.Sprintf("provedperson%d", i)).want(t, http.StatusAccepted, "")
				message := f.out.Last(t, iam.MessageVerification, address)
				if message.Code == "" {
					t.Fatal("registration did not deliver a proof")
				}
				r := f.call(t, "POST", "/verify/confirm", "", map[string]string{"identifier": address, "code": message.Code})
				r.want(t, http.StatusOK, "")
				var result signInResult
				decode(t, r.body, &result)
				if result.Status != "complete" || result.User == nil || result.Tokens == nil || result.User.TenantID != f.tenant {
					t.Fatalf("proof did not establish the intended directory account: %s", r.body)
				}
				if i == 0 && !result.User.EmailVerified || i == 1 && !result.User.PhoneVerified {
					t.Fatal("confirmed contact remained unverified")
				}
				f.call(t, "GET", "/me", result.Tokens.AccessToken, nil).want(t, http.StatusOK, "")
			})
		}
	})
	t.Run("AK-J03-C02_canonical_name_race_has_one_registration", func(t *testing.T) {
		results := make([]response, 2)
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				name := "racedperson"
				if i == 1 {
					name = "RACEDPERSON"
				}
				results[i], errs[i] = f.request(t.Context(), "POST", "/register", "", map[string]string{"identifier": fmt.Sprintf("raced-person%d@example.com", i), "username": name, "password": authtest.Password})
			}()
		}
		close(start)
		wg.Wait()
		accepted := 0
		for i, r := range results {
			noError(t, errs[i])
			if r.status == http.StatusAccepted {
				accepted++
				message := f.out.Last(t, iam.MessageVerification, fmt.Sprintf("raced-person%d@example.com", i))
				f.call(t, "POST", "/verify/confirm", "", map[string]string{"identifier": message.To, "code": message.Code}).want(t, http.StatusOK, "")
			} else {
				r.want(t, http.StatusBadRequest, "username_in_use")
			}
		}
		if accepted != 1 {
			t.Fatalf("accepted %d competing canonical registrations", accepted)
		}
		user, err := f.auth.User(t.Context(), iam.UserByUsername("racedperson"))
		noError(t, err)
		if user.Username != "racedperson" {
			t.Fatal("canonical winner has wrong identity")
		}
	})
	t.Run("AK-J03-C03_closed_and_invite_only_admission", func(t *testing.T) {
		for _, mode := range []iam.RegistrationMode{iam.RegistrationModeClosed, iam.RegistrationModeInviteOnly} {
			t.Run(string(mode), func(t *testing.T) {
				g := newFixture(t, proofRegistration(), authtest.WithConfig(func(c *authkit.Config) { c.Registration.NativeUserMode = mode }))
				r := g.register(t, "uninvited-person@example.com", "uninvitedperson")
				if mode == iam.RegistrationModeClosed {
					r.want(t, http.StatusNotFound, "")
				} else {
					r.want(t, http.StatusForbidden, "registration_disabled")
				}
				if len(g.out.Messages(iam.MessageVerification, "uninvited-person@example.com")) != 0 {
					t.Fatal("refused admission sent a signup proof")
				}
				_, err := g.auth.User(t.Context(), iam.UserByEmail("uninvited-person@example.com"))
				if !errors.Is(err, iam.ErrUserNotFound) {
					t.Fatalf("refused admission created an account: %v", err)
				}
			})
		}
	})
	t.Run("AK-J03-C04_verification_is_scoped_expiring_and_single_use", func(t *testing.T) {
		g := newFixture(t, proofRegistration())
		const email = "scoped-proof@example.com"
		g.register(t, email, "scopedproof").want(t, http.StatusAccepted, "")
		message := g.out.Last(t, iam.MessageVerification, email)
		g.call(t, "POST", "/verify/confirm", "", map[string]string{"identifier": "wrong-person@example.com", "code": message.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		id := iam.NewTenantID()
		noError(t, g.auth.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		view, err := g.auth.ForTenant(t.Context(), id)
		noError(t, err)
		server := httptest.NewServer(view.Handler())
		t.Cleanup(server.Close)
		other := &fixture{auth: view, server: server}
		other.call(t, "POST", "/verify/confirm", "", map[string]string{"identifier": email, "code": message.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		g.call(t, "POST", "/verify/confirm", "", map[string]string{"identifier": email, "code": message.Code}).want(t, http.StatusOK, "")
		g.call(t, "POST", "/verify/confirm", "", map[string]string{"identifier": email, "code": message.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		g.register(t, "expired-proof@example.com", "expiredproof").want(t, http.StatusAccepted, "")
		expired := g.out.Last(t, iam.MessageVerification, "expired-proof@example.com")
		g.expireProofs(t)
		g.call(t, "POST", "/verify/confirm", "", map[string]string{"identifier": expired.To, "code": expired.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		_, err = g.auth.User(t.Context(), iam.UserByEmail(expired.To))
		if !errors.Is(err, iam.ErrUserNotFound) {
			t.Fatal("expired proof created an account")
		}
	})
	t.Run("AK-J03-C05_abandon_requires_the_pending_password", func(t *testing.T) {
		const email = "abandoned-person@example.com"
		f.register(t, email, "abandonedperson").want(t, http.StatusAccepted, "")
		proof := f.out.Last(t, iam.MessageVerification, email)
		f.call(t, "POST", "/register/abandon", "", map[string]string{"identifier": email, "password": "wrong-secret"}).want(t, http.StatusNoContent, "")
		f.call(t, "POST", "/register/abandon", "", map[string]string{"identifier": email, "password": authtest.Password}).want(t, http.StatusNoContent, "")
		f.call(t, "POST", "/verify/confirm", "", map[string]string{"identifier": email, "code": proof.Code}).want(t, http.StatusUnauthorized, "invalid_code")
		f.register(t, email, "abandonedperson").want(t, http.StatusAccepted, "")
		fresh := f.out.Last(t, iam.MessageVerification, email)
		f.call(t, "POST", "/verify/confirm", "", map[string]string{"identifier": email, "code": fresh.Code}).want(t, http.StatusOK, "")
	})
}
