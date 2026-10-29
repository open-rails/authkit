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

const heldInterval = time.Second

// heldTiming makes the periodic check observable: a check that starts within
// half of heldInterval is a re-check, and one that starts later is periodic.
var heldTiming = authtest.WithConfig(func(c *authkit.Config) {
	c.SenderHealthInterval = heldInterval
	c.SenderHealthRecheck = 10 * time.Millisecond
})

// heldSender is a sender the test drives. Each CheckHealth waits for the
// test's answer. Send fails with failSends' error, hangs until its context
// ends with hangSends, and otherwise delivers to the Outbox.
type heldSender[M any] struct {
	deliver func(context.Context, M) error
	checks  chan chan<- error
	// sending and ended report a hung send's start and its context's end.
	sending chan struct{}
	ended   chan error
	mu      sync.Mutex
	sendErr error
	hang    bool
}

func newHeld[M any]() *heldSender[M] {
	return &heldSender[M]{checks: make(chan chan<- error), sending: make(chan struct{}, 1), ended: make(chan error, 1)}
}

func (h *heldSender[M]) Send(ctx context.Context, msg M) error {
	h.mu.Lock()
	err, hang := h.sendErr, h.hang
	h.mu.Unlock()
	if hang {
		h.sending <- struct{}{}
		<-ctx.Done()
		h.ended <- ctx.Err()
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	return h.deliver(ctx, msg)
}

func (h *heldSender[M]) CheckHealth(ctx context.Context) error {
	reply := make(chan error, 1)
	select {
	case h.checks <- reply:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-reply:
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

func (h *heldSender[M]) hangSends() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hang = true
}

// next waits for the next health check to start and returns its answer
// channel and how long after since it started. A started check proves the
// previous answer was recorded.
func (h *heldSender[M]) next(t *testing.T, since time.Time) (chan<- error, time.Duration) {
	t.Helper()
	select {
	case reply := <-h.checks:
		return reply, time.Since(since)
	case <-time.After(10 * time.Second):
		t.Fatal("no sender health check started")
		return nil, 0
	}
}

// recheck waits for a check brought forward from the interval.
func (h *heldSender[M]) recheck(t *testing.T, since time.Time) chan<- error {
	t.Helper()
	reply, after := h.next(t, since)
	if after >= heldInterval/2 {
		t.Fatalf("expected a quick re-check, but the check started %s later", after)
	}
	return reply
}

// periodic waits for a check that kept the normal interval.
func (h *heldSender[M]) periodic(t *testing.T, since time.Time) chan<- error {
	t.Helper()
	reply, after := h.next(t, since)
	if after < heldInterval/2 {
		t.Fatalf("expected the periodic check, but a check started %s later", after)
	}
	return reply
}

// quiet fails when a health check starts within d.
func (h *heldSender[M]) quiet(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-h.checks:
		t.Fatal("a health check was brought forward")
	case <-time.After(d):
	}
}

// answer finishes a started check and returns when it did.
func answer(check chan<- error, err error) time.Time {
	check <- err
	return time.Now()
}

func holdEmail() (*heldSender[iam.EmailMessage], authtest.Option) {
	h := newHeld[iam.EmailMessage]()
	return h, authtest.WithDeps(func(d *authkit.Deps) { h.deliver, d.Email = d.Email.Send, h })
}

func holdSMS() (*heldSender[iam.SMSMessage], authtest.Option) {
	h := newHeld[iam.SMSMessage]()
	return h, authtest.WithDeps(func(d *authkit.Deps) { h.deliver, d.SMS = d.SMS.Send, h })
}

func TestCriticalSenderHealth(t *testing.T) {
	outage := errors.New("owned sender outage")
	t.Run("AK-J40-C01_one_failed_check_keeps_the_channel_two_in_a_row_close_it_and_only_the_first_is_rechecked_quickly", func(t *testing.T) {
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
		check, _ := email.next(t, time.Now())
		if !f.auth.EmailAvailable() {
			t.Fatal("an unchecked sender was unavailable")
		}
		at := answer(check, outage)
		check = email.recheck(t, at)
		if _, err := f.auth.EmailHealth(); !f.auth.EmailAvailable() || err != nil || probe() != nil {
			t.Fatalf("one failed check closed the channel: %v", err)
		}
		at = answer(check, outage)
		eventually(t, "second failed check closes email", func() bool { return !f.auth.EmailAvailable() })
		if checked, err := f.auth.EmailHealth(); checked.IsZero() || !errors.Is(err, outage) || !errors.Is(probe(), outage) {
			t.Fatalf("closed channel lost its checked time or cause: %s %v", checked, err)
		}
		start().want(t, http.StatusServiceUnavailable, "email_unavailable")
		// A closed channel goes back to the normal interval, not the re-check.
		check = email.periodic(t, at)
		at = answer(check, nil)
		eventually(t, "passing check reopens email", f.auth.EmailAvailable)
		start().want(t, http.StatusAccepted, "")
		f.out.Last(t, iam.MessageVerification, u.Email)
		email.periodic(t, at)
	})
	t.Run("AK-J40-C02_failed_sends_bring_one_check_forward_and_never_decide_health", func(t *testing.T) {
		sms, held := holdSMS()
		f := newFixture(t, held, heldTiming)
		const phone = "+12025550181"
		_, err := f.auth.CreateUser(t.Context(), iam.NewUser{Phone: phone, PhoneVerified: true, Username: "heldsmsuser"})
		noError(t, err)
		start := func() response {
			return f.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": phone, "mode": "login"})
		}
		noError(t, f.auth.Start(context.Background()))
		check, _ := sms.next(t, time.Now())
		answer(check, nil)

		sms.failSends(outage)
		start().want(t, http.StatusBadGateway, "sms_delivery_failed")
		check = sms.recheck(t, time.Now())
		// While that check runs, more failed sends keep one request between them.
		start().want(t, http.StatusBadGateway, "sms_delivery_failed")
		start().want(t, http.StatusBadGateway, "sms_delivery_failed")
		if _, err := f.auth.SMSHealth(); !f.auth.SMSAvailable() || err != nil {
			t.Fatalf("failed sends closed the channel: %v", err)
		}
		check = sms.recheck(t, answer(check, nil))
		check = sms.periodic(t, answer(check, nil))

		// A successful send does not clear a failed check.
		check = sms.recheck(t, answer(check, outage))
		sms.failSends(nil)
		start().want(t, http.StatusAccepted, "")
		answer(check, outage)
		eventually(t, "second failed check closes SMS despite the send between", func() bool { return !f.auth.SMSAvailable() })
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
		check, _ := email.next(t, time.Now())
		check = email.recheck(t, answer(check, outage))
		parked()
		sent := len(f.out.Messages(iam.MessageVerification, *unproven.Email))
		if sent == 0 {
			t.Fatal("one failed check withheld the verification code")
		}
		at := answer(check, outage)
		eventually(t, "second failed check closes email", func() bool { return !f.auth.EmailAvailable() })
		login().want(t, http.StatusServiceUnavailable, "verification_unavailable")
		sessions, err := f.auth.Sessions(t.Context(), unproven.ID)
		noError(t, err)
		if len(sessions) != 0 || len(f.out.Messages(iam.MessageVerification, *unproven.Email)) != sent {
			t.Fatal("closed channel issued a session or claimed a code")
		}
		answer(email.periodic(t, at), nil)
		eventually(t, "passing check reopens email", f.auth.EmailAvailable)
		parked()
	})
	t.Run("AK-J40-C04_a_send_its_caller_abandons_or_that_hits_the_send_timeout_brings_no_check_forward", func(t *testing.T) {
		email, held := holdEmail()
		f := newFixture(t, held, heldTiming, authtest.WithConfig(func(c *authkit.Config) {
			c.SenderHealthInterval = time.Minute
			c.Registration.VerificationSendTimeout = 200 * time.Millisecond
		}))
		u := f.user(t)
		body := map[string]string{"identifier": u.Email, "mode": "login"}
		noError(t, f.auth.Start(context.Background()))
		check, _ := email.next(t, time.Now())
		answer(check, nil)
		email.hangSends()

		_, _ = f.request(t.Context(), "POST", "/passwordless/start", "", body)
		<-email.sending
		if err := <-email.ended; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("hung send did not hit the send timeout: %v", err)
		}
		email.quiet(t, 300*time.Millisecond)

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = f.request(ctx, "POST", "/passwordless/start", "", body)
		}()
		select {
		case <-email.sending:
		case <-time.After(10 * time.Second):
			t.Fatal("abandoned request never reached the sender")
		}
		cancel()
		<-done
		if err := <-email.ended; !errors.Is(err, context.Canceled) {
			t.Fatalf("abandoned send did not see its caller leave: %v", err)
		}
		email.quiet(t, 300*time.Millisecond)
	})
}
