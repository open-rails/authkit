package critical_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// heldSender is a sender the test drives: each CheckHealth waits for the
// test's answer (next), and Send fails with failSends' error, else delivers
// to the Outbox.
type heldSender[M any] struct {
	deliver func(context.Context, M) error
	checks  chan chan<- error
	mu      sync.Mutex
	sendErr error
}

func (h *heldSender[M]) Send(ctx context.Context, msg M) error {
	h.mu.Lock()
	err := h.sendErr
	h.mu.Unlock()
	if err != nil {
		return err
	}
	return h.deliver(ctx, msg)
}

func (h *heldSender[M]) CheckHealth(ctx context.Context) error {
	answer := make(chan error, 1)
	select {
	case h.checks <- answer:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-answer:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *heldSender[M]) failSends(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sendErr = err
}

// next waits for the next health check to start and returns its answer
// channel. A started check proves the previous answer was recorded.
func (h *heldSender[M]) next(t *testing.T) chan<- error {
	t.Helper()
	select {
	case answer := <-h.checks:
		return answer
	case <-time.After(10 * time.Second):
		t.Fatal("no sender health check started")
		return nil
	}
}

// An hour-long interval never elapses here, so a check that starts after a
// failure is the quick re-check.
var heldTiming = authtest.WithConfig(func(c *authkit.Config) {
	c.SenderHealthInterval = time.Hour
	c.SenderHealthRecheck = 10 * time.Millisecond
})

func holdEmail() (*heldSender[iam.EmailMessage], authtest.Option) {
	h := &heldSender[iam.EmailMessage]{checks: make(chan chan<- error)}
	return h, authtest.WithDeps(func(d *authkit.Deps) { h.deliver, d.Email = d.Email.Send, h })
}

func holdSMS() (*heldSender[iam.SMSMessage], authtest.Option) {
	h := &heldSender[iam.SMSMessage]{checks: make(chan chan<- error)}
	return h, authtest.WithDeps(func(d *authkit.Deps) { h.deliver, d.SMS = d.SMS.Send, h })
}

func TestCriticalSenderHealth(t *testing.T) {
	outage := errors.New("owned sender outage")
	t.Run("AK-J40-C01_one_failed_check_keeps_the_channel_and_two_in_a_row_close_it_until_a_quick_recheck_passes", func(t *testing.T) {
		email, held := holdEmail()
		f := newFixture(t, held, heldTiming)
		u := f.user(t)
		start := func() response {
			return f.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": u.Email, "mode": "login"})
		}
		probe := func() error {
			for _, p := range f.auth.Probes() {
				if p.Name == "authkit_email" {
					return p.Check(t.Context())
				}
			}
			t.Fatal("configured email sender omitted its probe")
			return nil
		}
		noError(t, f.auth.Start(context.Background()))
		check := email.next(t)
		if !f.auth.EmailAvailable() {
			t.Fatal("an unchecked sender was unavailable")
		}
		check <- outage
		check = email.next(t)
		if _, err := f.auth.EmailHealth(); !f.auth.EmailAvailable() || err != nil || probe() != nil {
			t.Fatalf("one failed check closed the channel: %v", err)
		}
		check <- outage
		check = email.next(t)
		if at, err := f.auth.EmailHealth(); f.auth.EmailAvailable() || at.IsZero() || !errors.Is(err, outage) || !errors.Is(probe(), outage) {
			t.Fatalf("two failed checks in a row left the channel open: %s %v", at, err)
		}
		start().want(t, http.StatusServiceUnavailable, "email_unavailable")
		check <- nil
		eventually(t, "passing re-check reopens email", f.auth.EmailAvailable)
		start().want(t, http.StatusAccepted, "")
		f.out.Last(t, iam.MessageVerification, u.Email)
	})
	t.Run("AK-J40-C02_failed_sends_keep_the_channel_and_bring_its_check_forward_and_a_successful_send_clears_a_failed_check", func(t *testing.T) {
		sms, held := holdSMS()
		f := newFixture(t, held, heldTiming)
		const phone = "+12025550181"
		_, err := f.auth.CreateUser(t.Context(), iam.NewUser{Phone: phone, PhoneVerified: true, Username: "heldsmsuser"})
		noError(t, err)
		start := func() response {
			return f.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": phone, "mode": "login"})
		}
		open := func(why string) {
			t.Helper()
			if _, err := f.auth.SMSHealth(); !f.auth.SMSAvailable() || err != nil {
				t.Fatalf("%s closed the channel: %v", why, err)
			}
		}
		noError(t, f.auth.Start(context.Background()))
		sms.next(t) <- nil
		eventually(t, "first SMS check recorded", func() bool { at, _ := f.auth.SMSHealth(); return !at.IsZero() })

		sms.failSends(outage)
		start().want(t, http.StatusBadGateway, "sms_delivery_failed")
		check := sms.next(t)
		start().want(t, http.StatusBadGateway, "sms_delivery_failed")
		open("failed sends")
		check <- outage
		check = sms.next(t)
		open("failed sends and one failed check")

		sms.failSends(nil)
		start().want(t, http.StatusAccepted, "")
		check <- outage
		check = sms.next(t)
		open("a failed check after a successful send")
		check <- outage
		sms.next(t)
		if _, err := f.auth.SMSHealth(); f.auth.SMSAvailable() || !errors.Is(err, outage) {
			t.Fatalf("two failed checks in a row left SMS open: %v", err)
		}
		start().want(t, http.StatusServiceUnavailable, "sms_unavailable")
	})
	t.Run("AK-J40-C03_unproven_sign_in_keeps_its_code_through_one_failed_check_and_is_refused_after_two_in_a_row", func(t *testing.T) {
		email, held := holdEmail()
		f := newFixture(t, proofRegistration(), held, heldTiming)
		unproven, err := f.auth.CreateUser(t.Context(), iam.NewUser{Email: "unproven-held@example.com", Username: "unprovenheld", Password: authtest.Password})
		noError(t, err)
		login := func() response {
			return f.call(t, "POST", "/password/login", "", map[string]string{"identifier": *unproven.Email, "password": authtest.Password})
		}
		parked := func() {
			t.Helper()
			r := login()
			r.want(t, http.StatusOK, "")
			var out signInResult
			decode(t, r.body, &out)
			if out.Status != "verification_required" || out.Tokens != nil {
				t.Fatalf("unproven sign-in was not parked at its code: %+v", out)
			}
		}
		noError(t, f.auth.Start(context.Background()))
		email.next(t) <- outage
		check := email.next(t)
		parked()
		sent := len(f.out.Messages(iam.MessageVerification, *unproven.Email))
		if sent == 0 {
			t.Fatal("one failed check withheld the verification code")
		}
		// That code was a successful send, which cleared the failed check.
		check <- outage
		check = email.next(t)
		check <- outage
		check = email.next(t)
		login().want(t, http.StatusServiceUnavailable, "verification_unavailable")
		sessions, err := f.auth.Sessions(t.Context(), unproven.ID)
		noError(t, err)
		if len(sessions) != 0 || len(f.out.Messages(iam.MessageVerification, *unproven.Email)) != sent {
			t.Fatal("closed channel issued a session or claimed a code")
		}
		check <- nil
		eventually(t, "passing re-check reopens email", f.auth.EmailAvailable)
		parked()
	})
}
