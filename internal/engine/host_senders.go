package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/lang"
)

// A flow that must deliver with no sender configured answers email_unavailable
// or sms_unavailable (503), never a silent success.
var (
	errEmailNotConfigured = errmodel.E(errmodel.CodeEmailUnavailable, errmodel.WithCause(errors.New("no email sender: set Deps.Email")))
	errSMSNotConfigured   = errmodel.E(errmodel.CodeSMSUnavailable, errmodel.WithCause(errors.New("no SMS sender: set Deps.SMS")))
)

// sendEmail delivers msg under the per-send timeout. While the sender is
// unhealthy it refuses at once with ErrEmailUnavailable.
func (s *Engine) sendEmail(ctx context.Context, msg iam.EmailMessage) error {
	if !s.EmailAvailable() {
		return errmodel.ErrEmailUnavailable
	}
	return emailDeliveryError(s.deliver(ctx, &s.emailHealth, func(ctx context.Context) error { return s.email.Send(ctx, msg) }))
}

// sendSMS is sendEmail for text messages, within the SMS policy: an allowed
// region, the send limits, and a code's origin.
func (s *Engine) sendSMS(ctx context.Context, msg iam.SMSMessage) error {
	if !s.SMSAvailable() {
		return errmodel.ErrSMSUnavailable
	}
	region, err := s.smsRegion(msg.To)
	if err != nil {
		return err
	}
	if err := s.admitSMS(ctx, msg, region); err != nil {
		return err
	}
	if msg.Domain == "" && msg.Code != "" {
		msg.Domain = s.codeDomain()
	}
	return smsDeliveryError(s.deliver(ctx, &s.smsHealth, func(ctx context.Context) error { return s.sms.Send(ctx, msg) }))
}

// messageLanguage is a message's language: preferred (the account's), else
// the request's, else Config.Languages.Default.
func (s *Engine) messageLanguage(ctx context.Context, preferred string) string {
	if l := lang.Normalize(preferred); l != "" {
		return l
	}
	if l := lang.Request(ctx); l != "" {
		return l
	}
	if s.cfg.Languages.Default != "" {
		return s.cfg.Languages.Default
	}
	return lang.Default
}

// userLanguage is messageLanguage for an account's stored preference.
func (s *Engine) userLanguage(ctx context.Context, userID string) string {
	preferred := ""
	if s.pg != nil && userID != "" {
		preferred, _ = s.q.UserPreferredLanguage(ctx, userID)
	}
	return s.messageLanguage(ctx, preferred)
}

// senderHealth is a sender's latest health verdict. Only checks decide it: it
// turns unhealthy after two failed checks in a row, so one blip never hides
// the sender's flows, and the next passing check clears it. A sender counts
// as healthy until then, so startup never waits on the provider.
type senderHealth struct {
	mu        sync.Mutex
	checkedAt time.Time
	err       error
	failures  int
	// recheck asks the watcher for an early check after a failed send.
	recheck chan struct{}
}

func (h *senderHealth) get() (time.Time, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.checkedAt, h.err
}

// record notes the outcome of a check that started at at, and reports
// whether the sender is now unhealthy.
func (h *senderHealth) record(at time.Time, err error) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkedAt = at
	if err == nil {
		h.failures, h.err = 0, nil
		return false
	}
	h.failures++
	if h.failures > 1 {
		h.err = err
	}
	return h.err != nil
}

// EmailHealth is the Deps.Email health verdict and when the check behind it
// started; a zero time means no check has run.
func (s *Engine) EmailHealth() (time.Time, error) { return s.emailHealth.get() }

// SMSHealth is EmailHealth for Deps.SMS.
func (s *Engine) SMSHealth() (time.Time, error) { return s.smsHealth.get() }

// EmailAvailable reports whether email flows are offered: Deps.Email is set
// and its health verdict is not a failure.
func (s *Engine) EmailAvailable() bool {
	_, err := s.EmailHealth()
	return s.email != nil && err == nil
}

// SMSAvailable is EmailAvailable for Deps.SMS and phone flows.
func (s *Engine) SMSAvailable() bool {
	_, err := s.SMSHealth()
	return s.sms != nil && err == nil
}

// startSenderHealth runs each sender's CheckHealth now and then every
// Config.SenderHealthInterval until Close. After the first failed check, or a
// failed send, the next check comes after Config.SenderHealthRecheck instead.
func (s *Engine) startSenderHealth() {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if s.stopHealth != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.stopHealth = cancel
	if s.email != nil {
		go s.watchSender(ctx, "email", s.email.CheckHealth, &s.emailHealth)
	}
	if s.sms != nil {
		go s.watchSender(ctx, "SMS", s.sms.CheckHealth, &s.smsHealth)
	}
}

func (s *Engine) watchSender(ctx context.Context, channel string, check func(context.Context) error, h *senderHealth) {
	for {
		started := time.Now()
		checkCtx, done := context.WithTimeout(ctx, time.Minute)
		err := check(checkCtx)
		done()
		if ctx.Err() != nil {
			return
		}
		closed := h.record(started, err)
		wait := s.cfg.SenderHealthInterval
		if err != nil {
			slog.WarnContext(ctx, "authkit: "+channel+" health check failed; a second failed check in a row closes its flows until a check passes", "error", err, "flows_closed", closed)
			if !closed {
				wait = s.cfg.SenderHealthRecheck
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-h.recheck:
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.cfg.SenderHealthRecheck):
			}
		}
	}
}

func (s *Engine) stopSenderHealth() {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if s.stopHealth != nil {
		s.stopHealth()
	}
}

func emailDeliveryError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", errmodel.ErrEmailDeliveryFailed, err)
}

func smsDeliveryError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", errmodel.ErrSMSDeliveryFailed, err)
}

// deliver runs one provider send under Registration.VerificationSendTimeout,
// so an unreachable provider cannot hang the request that triggered it. Sends
// never decide h: one may fail for a single recipient, or report a success it
// could not confirm. A send that fails while its caller and timeout are still
// alive only asks for an early check.
func (s *Engine) deliver(ctx context.Context, h *senderHealth, send func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Registration.VerificationSendTimeout)
	defer cancel()
	err := send(ctx)
	if err != nil && ctx.Err() == nil {
		select {
		case h.recheck <- struct{}{}:
		default:
		}
	}
	return err
}
