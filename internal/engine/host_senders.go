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

// HasEmailSender reports whether Deps.Email is set.
func (s *Engine) HasEmailSender() bool { return s.email != nil }

// sendEmail delivers msg under the per-send timeout.
func (s *Engine) sendEmail(ctx context.Context, msg iam.EmailMessage) error {
	return emailDeliveryError(s.withSendTimeout(ctx, func(ctx context.Context) error { return s.email(ctx, msg) }))
}

// sendSMS delivers msg under the per-send timeout.
func (s *Engine) sendSMS(ctx context.Context, msg iam.SMSMessage) error {
	return smsDeliveryError(s.withSendTimeout(ctx, func(ctx context.Context) error { return s.sms(ctx, msg) }))
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

// smsHealth is the latest Deps.SMSHealth verdict. SMS counts as available
// until a check has failed, so startup never waits on the provider.
type smsHealth struct {
	mu        sync.Mutex
	checkedAt time.Time
	err       error
	stop      context.CancelFunc
}

// checkSMSHealth runs Deps.SMSHealth and records its verdict, which gates
// phone flows: a failure disables them and the next pass re-arms them.
func (s *Engine) checkSMSHealth(ctx context.Context) error {
	if s.smsCheck == nil {
		return nil
	}
	started := time.Now()
	err := s.smsCheck(ctx)
	s.smsHealth.mu.Lock()
	s.smsHealth.checkedAt, s.smsHealth.err = started, err
	s.smsHealth.mu.Unlock()
	if err != nil {
		slog.WarnContext(ctx, "authkit: SMS health check failed; phone flows are unavailable until it passes", "error", err)
	}
	return err
}

// SMSHealth is the latest Deps.SMSHealth verdict and when that check started;
// a zero time means no check has run.
func (s *Engine) SMSHealth() (time.Time, error) {
	s.smsHealth.mu.Lock()
	defer s.smsHealth.mu.Unlock()
	return s.smsHealth.checkedAt, s.smsHealth.err
}

// SMSAvailable reports whether phone flows are offered: Deps.SMS is set and
// the latest health check, if any, passed.
func (s *Engine) SMSAvailable() bool {
	_, err := s.SMSHealth()
	return s.sms != nil && err == nil
}

// startSMSHealth runs Deps.SMSHealth now and every Config.SMSHealthInterval
// until Close.
func (s *Engine) startSMSHealth() {
	s.smsHealth.mu.Lock()
	defer s.smsHealth.mu.Unlock()
	if s.smsCheck == nil || s.smsHealth.stop != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.smsHealth.stop = cancel
	go func() {
		for {
			check, done := context.WithTimeout(ctx, time.Minute)
			_ = s.checkSMSHealth(check)
			done()
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.cfg.SMSHealthInterval):
			}
		}
	}()
}

func (s *Engine) stopSMSHealth() {
	s.smsHealth.mu.Lock()
	defer s.smsHealth.mu.Unlock()
	if s.smsHealth.stop != nil {
		s.smsHealth.stop()
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
