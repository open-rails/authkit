package authcore

import (
	"context"
	"fmt"
	stdlog "log"
	"strings"

	authkit "github.com/open-rails/authkit"
)

// VerificationMessage is the payload AuthKit hands a sender: a code, a link, or
// both. Purpose lets senders vary copy without adding new methods.
type VerificationMessage struct {
	// Fixed-length numeric code for manual entry (optional).
	Code string
	// AuthKit-built scanner-safe verification link (optional).
	LinkURL string
	// Purpose lets senders vary copy without adding new sender methods.
	Purpose string
}

func (m VerificationMessage) Validate() error {
	if strings.TrimSpace(m.Code) == "" && strings.TrimSpace(m.LinkURL) == "" {
		return fmt.Errorf("verification message must contain at least one of code or link URL")
	}
	return nil
}

var (
	ErrEmailDeliveryFailed = authkit.ErrEmailDeliveryFailed
	ErrSMSDeliveryFailed   = authkit.ErrSMSDeliveryFailed
)

// EmailSender sends verification/login/reset emails.
type EmailSender interface {
	SendVerification(ctx context.Context, email, username string, msg VerificationMessage) error
	SendPasswordResetLink(ctx context.Context, email, username, resetURL string) error
	SendLoginCode(ctx context.Context, email, username, code string) error
	SendWelcome(ctx context.Context, email, username string) error
}

// SMSSender sends verification/login/reset SMS messages.
type SMSSender interface {
	SendVerification(ctx context.Context, phone string, msg VerificationMessage) error
	SendPasswordResetLink(ctx context.Context, phone, resetURL string) error
	SendLoginCode(ctx context.Context, phone, code string) error
}

// SMSHealthChecker is an optional capability for SMS senders that can verify,
// without sending a message, that they are configured to actually deliver
// (valid credentials, an attached sender, and a verified/registered number).
// CheckHealth returns nil when delivery is expected to succeed, or a
// descriptive error explaining why it will not (e.g. an unverified toll-free
// sender that would otherwise fail silently with Twilio error 30032).
type SMSHealthChecker interface {
	CheckHealth(ctx context.Context) error
}

// WithEmailSender sets the email sender dependency.
func (s *Service) WithEmailSender(sender EmailSender) *Service { s.email = sender; return s }

// WithSMSSender sets the SMS sender dependency.
func (s *Service) WithSMSSender(sender SMSSender) *Service { s.sms = sender; return s }

// HasEmailSender returns true if an email sender is configured.
func (s *Service) HasEmailSender() bool { return s.email != nil }

// HasSMSSender returns true if an SMS sender is configured.
func (s *Service) HasSMSSender() bool { return s.sms != nil }

// CheckSMSHealth probes whether the configured SMS sender can actually deliver,
// without sending a message, when the sender implements SMSHealthChecker. The
// result is cached and gates phone-based flows via SMSAvailable. It returns the
// probe error (nil = healthy) so callers can log it. When no sender is
// configured or the sender cannot self-check, it records healthy=true (delivery
// readiness is then governed solely by sender presence, as before).
func (s *Service) CheckSMSHealth(ctx context.Context) error {
	if s == nil {
		return nil
	}
	checker, ok := s.sms.(SMSHealthChecker)
	if s.sms == nil || !ok {
		s.smsHealthy.Store(true)
		s.smsHealthReason.Store("")
		s.smsHealthChecked.Store(true)
		return nil
	}
	err := checker.CheckHealth(ctx)
	if err != nil {
		s.smsHealthy.Store(false)
		s.smsHealthReason.Store(err.Error())
	} else {
		s.smsHealthy.Store(true)
		s.smsHealthReason.Store("")
	}
	s.smsHealthChecked.Store(true)
	return err
}

// SMSHealthy reports the last CheckSMSHealth result. It is true until a check
// has run (legacy behavior: assume healthy when a sender is present).
func (s *Service) SMSHealthy() bool {
	if s == nil {
		return false
	}
	if !s.smsHealthChecked.Load() {
		return true
	}
	return s.smsHealthy.Load()
}

// SMSHealthReason returns the reason SMS was last found unhealthy, if any.
func (s *Service) SMSHealthReason() string {
	if s == nil {
		return ""
	}
	if r, ok := s.smsHealthReason.Load().(string); ok {
		return r
	}
	return ""
}

// SMSAvailable reports whether phone-based flows should be offered: a sender is
// configured and (if a health check has run) it was found able to deliver.
func (s *Service) SMSAvailable() bool {
	return s.HasSMSSender() && s.SMSHealthy()
}

func emailDeliveryError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrEmailDeliveryFailed, err)
}

func smsDeliveryError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrSMSDeliveryFailed, err)
}

// ValidateVerificationConfiguration ensures registration verification policy
// can be satisfied by currently configured delivery senders.
func (s *Service) ValidateVerificationConfiguration() error {
	if s == nil {
		return nil
	}
	policy := s.opts.RegistrationVerificationPolicy()
	hasVerificationSender := s.email != nil || s.sms != nil

	if policy == RegistrationVerificationRequired && !hasVerificationSender {
		return fmt.Errorf("authkit: registration verification policy is %q but no email or SMS sender is configured", RegistrationVerificationRequired)
	}

	if !hasVerificationSender {
		s.verifyWarnOnce.Do(func() {
			stdlog.Printf("authkit: warning: no email or SMS sender configured; verification delivery is disabled")
		})
	}
	return nil
}
