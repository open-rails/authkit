package critical_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

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
		noError(t, g.auth.CreateTenant(t.Context(), iam.Tenant{ID: id, Slug: "registration-other"}))
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
	t.Run("AK-J03-C06_taken_contact_answers_like_a_fresh_one", func(t *testing.T) {
		owner := f.user(t)
		phoneOwner, err := f.auth.CreateUser(t.Context(), iam.NewUser{Phone: "+12025550188", Username: "takenphoneowner", Password: authtest.Password, PhoneVerified: true})
		noError(t, err)
		for i, address := range []string{owner.Email, *phoneOwner.Phone} {
			f.register(t, address, fmt.Sprintf("takenattempt%d", i)).want(t, http.StatusAccepted, "")
			if got := f.out.Messages(iam.MessageVerification, address); len(got) != 0 {
				t.Fatalf("taken %s received a sign-up code: %+v", address, got)
			}
			notice := f.out.Last(t, iam.MessageAccountExists, address)
			if notice.Token == "" {
				t.Fatalf("notice to %s carries no reset link", address)
			}
			f.call(t, "POST", "/password/reset/confirm", "", map[string]string{"token": notice.Token, "new_password": fmt.Sprintf("Owner-reset-%d-password", i)}).want(t, http.StatusNoContent, "")
		}
		f.register(t, "fresh-beside-taken@example.com", "freshbesidetaken").want(t, http.StatusAccepted, "")
		f.out.Last(t, iam.MessageVerification, "fresh-beside-taken@example.com")

		// A username held by a pending sign-up is refused whether or not the
		// email is taken, so the refusal says nothing about the email.
		other := f.user(t)
		f.register(t, "holds-a-name@example.com", "pendingname").want(t, http.StatusAccepted, "")
		f.register(t, "free-address@example.com", "pendingname").want(t, http.StatusBadRequest, "username_in_use")
		f.register(t, other.Email, "pendingname").want(t, http.StatusBadRequest, "username_in_use")

		// Every follow-up to a sign-up looks the same for a free and a taken
		// address, and a second sign-up never reaches a pending one's code.
		const attempt = "Attempt-password-42"
		holder := f.user(t)
		free := fmt.Sprintf("never-registered-%d@example.com", time.Now().UnixNano())
		for i, address := range []string{free, holder.Email} {
			name := fmt.Sprintf("probename%d", i)
			signUp := func(username string) response {
				return f.call(t, "POST", "/register", "", map[string]string{"identifier": address, "username": username, "password": attempt})
			}
			held := func() bool {
				var a struct {
					Username struct {
						Available bool `json:"available"`
					} `json:"username"`
				}
				decode(t, f.call(t, "GET", "/register/availability?username="+name, "", nil).body, &a)
				return !a.Username.Available
			}
			signUp(name).want(t, http.StatusAccepted, "")
			if !held() {
				t.Fatalf("sign-up %d left its username free", i)
			}
			signUp(name+"x").want(t, http.StatusBadRequest, "email_in_use")
			r := f.call(t, "POST", "/password/login", "", map[string]string{"identifier": address, "password": attempt})
			r.want(t, http.StatusOK, "")
			var login signInResult
			decode(t, r.body, &login)
			if login.Status != "verification_required" || login.Tokens != nil {
				t.Fatalf("sign-up %d password answered %s", i, r.body)
			}
			for range 6 {
				f.call(t, "POST", "/password/login", "", map[string]string{"identifier": address, "password": attempt}).want(t, http.StatusOK, "")
			}
			sent := iam.MessageVerification
			if i == 1 {
				sent = iam.MessageAccountExists
			}
			// The sign-up's message plus six re-sends; the seventh sign-in sends nothing.
			if got := len(f.out.Messages(sent, address)); got != 7 {
				t.Fatalf("sign-up %d sent %d messages to its address, want 7", i, got)
			}
			f.call(t, "POST", "/register/abandon", "", map[string]string{"identifier": address, "password": attempt}).want(t, http.StatusNoContent, "")
			if held() {
				t.Fatalf("abandoned sign-up %d kept its username", i)
			}
		}
		f.signIn(t, holder)

		session := f.signIn(t, other)
		f.call(t, "PUT", "/me/email", session.AccessToken, map[string]string{"email": owner.Email}).want(t, http.StatusAccepted, "")
		if got := f.out.Messages(iam.MessageAccountExists, owner.Email); len(got) != 2 {
			t.Fatalf("email change onto a taken address sent %d notices to its owner, want 2", len(got))
		}

		r := f.call(t, "GET", "/register/availability?username=freename7&email="+url.QueryEscape(owner.Email)+"&phone_number="+url.QueryEscape(*phoneOwner.Phone), "", nil)
		r.want(t, http.StatusOK, "")
		var answered map[string]json.RawMessage
		decode(t, r.body, &answered)
		if answered["username"] == nil || string(answered["email"]) != "null" || string(answered["phone_number"]) != "null" {
			t.Fatalf("availability answered beyond the username: %s", r.body)
		}
		f.call(t, "GET", "/register/availability?email="+url.QueryEscape(owner.Email), "", nil).want(t, http.StatusBadRequest, "invalid_request")

		g := newFixture(t, proofRegistration(), authtest.WithDeps(func(d *authkit.Deps) { d.Email = refuseAccountExists{d.Email} }))
		u := g.user(t)
		g.register(t, u.Email, "fallbackattempt").want(t, http.StatusAccepted, "")
		if g.out.Last(t, iam.MessagePasswordReset, u.Email).Token == "" {
			t.Fatal("a sender without account_exists copy got no reset link")
		}
	})
}

// refuseAccountExists is a host sender with no copy for account_exists.
type refuseAccountExists struct{ authkit.EmailSender }

func (r refuseAccountExists) Send(ctx context.Context, m iam.EmailMessage) error {
	if m.Kind == iam.MessageAccountExists {
		return errors.New("no copy for account_exists")
	}
	return r.EmailSender.Send(ctx, m)
}
