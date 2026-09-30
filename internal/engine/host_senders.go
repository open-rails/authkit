package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/lang"
)

// sendEmail delivers msg under the per-send timeout. While the sender's
// health check fails it refuses at once with ErrEmailUnavailable.
func (s *Engine) sendEmail(ctx context.Context, msg iam.EmailMessage) error {
	if !s.EmailAvailable() {
		return errmodel.ErrEmailUnavailable
	}
	return emailDeliveryError(s.withSendTimeout(ctx, func(ctx context.Context) error { return s.email.Send(ctx, msg) }))
}

// sendSMS is sendEmail for text messages.
func (s *Engine) sendSMS(ctx context.Context, msg iam.SMSMessage) error {
	if !s.SMSAvailable() {
		return errmodel.ErrSMSUnavailable
	}
	return smsDeliveryError(s.withSendTimeout(ctx, func(ctx context.Context) error { return s.sms.Send(ctx, msg) }))
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

// senderHealth is a sender's latest CheckHealth verdict. A sender counts as
// healthy until a check fails, so startup never waits on the provider.
type senderHealth struct {
	mu        sync.Mutex
	checkedAt time.Time
	err       error
}

func (h *senderHealth) get() (time.Time, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.checkedAt, h.err
}

func (h *senderHealth) set(checkedAt time.Time, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkedAt, h.err = checkedAt, err
}

// EmailHealth is the latest Deps.Email health verdict and when that check
// started; a zero time means no check has run.
func (s *Engine) EmailHealth() (time.Time, error) { return s.emailHealth.get() }

// SMSHealth is EmailHealth for Deps.SMS.
func (s *Engine) SMSHealth() (time.Time, error) { return s.smsHealth.get() }

// EmailAvailable reports whether email flows are offered: Deps.Email is set
// and its latest health check, if any, passed.
func (s *Engine) EmailAvailable() bool {
	_, err := s.EmailHealth()
	return s.email != nil && err == nil
}

// SMSAvailable is EmailAvailable for Deps.SMS and phone flows.
func (s *Engine) SMSAvailable() bool {
	_, err := s.SMSHealth()
	return s.sms != nil && err == nil
}

// startSenderHealth runs each sender's CheckHealth now and every
// Config.SenderHealthInterval until Close. A failing check makes its channel
// unavailable; the next passing one re-arms it.
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
		h.set(started, err)
		if err != nil {
			slog.WarnContext(ctx, "authkit: "+channel+" health check failed; its flows are unavailable until it passes", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.SenderHealthInterval):
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

// withSendTimeout runs one provider send under
// Registration.VerificationSendTimeout, so an unreachable provider cannot hang
// the request that triggered it.
func (s *Engine) withSendTimeout(ctx context.Context, send func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Registration.VerificationSendTimeout)
	defer cancel()
	return send(ctx)
}
