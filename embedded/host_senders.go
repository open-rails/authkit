package embedded

import (
	"context"
	"fmt"
	stdlog "log"
	"strings"
	"sync/atomic"
	"time"

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

// ContactChange is delivered to the PREVIOUS address after a recovery
// identifier (email or phone) was replaced, so a hijacked change is visible to
// the account's real owner.
type ContactChange struct {
	// Field is "email" or "phone".
	Field string
	// NewValue is the replacement address as stored.
	NewValue string
}

// DeviceKeyNotice describes a native-client device key just enrolled on an
// EXISTING account (#293), so a key added through a compromised mailbox is
// visible to the account's real owner.
type DeviceKeyNotice struct {
	Label     string
	CreatedAt time.Time
}

// EmailSender sends verification/login/reset/notice emails.
type EmailSender interface {
	SendVerification(ctx context.Context, email, username string, msg VerificationMessage) error
	SendPasswordResetLink(ctx context.Context, email, username, resetURL string) error
	SendAccountRegistrationInvite(ctx context.Context, email, inviteURL string) error
	SendLoginCode(ctx context.Context, email, username, code string) error
	SendWelcome(ctx context.Context, email, username string) error
	// SendContactChanged goes to the address that was just REPLACED.
	SendContactChanged(ctx context.Context, email, username string, change ContactChange) error
	// SendDeviceKeyEnrolled tells the account's address that a new device key
	// can now sign in as it.
	SendDeviceKeyEnrolled(ctx context.Context, email, username string, notice DeviceKeyNotice) error
}

// SMSSender sends verification/login/reset/notice SMS messages.
type SMSSender interface {
	SendVerification(ctx context.Context, phone string, msg VerificationMessage) error
	SendPasswordResetLink(ctx context.Context, phone, resetURL string) error
	SendLoginCode(ctx context.Context, phone, code string) error
	// SendContactChanged goes to the number that was just REPLACED.
	SendContactChanged(ctx context.Context, phone string, change ContactChange) error
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

// HasEmailSender returns true if an email sender is configured.
func (s *engine) HasEmailSender() bool { return s.email != nil }

// HasSMSSender returns true if an SMS sender is configured.
func (s *engine) HasSMSSender() bool { return s.sms != nil }

// smsHealth is the latest SMS deliverability verdict. It is optimistic: SMS
// counts as available until a check has failed, so startup never waits on the
// SMS provider, and every later check overwrites the verdict.
type smsHealth struct {
	checked atomic.Bool
	healthy atomic.Bool
}

func (h *smsHealth) record(err error) {
	h.healthy.Store(err == nil)
	h.checked.Store(true)
}

func (h *smsHealth) available() bool { return !h.checked.Load() || h.healthy.Load() }

// CheckSMSHealth probes, without sending a message, whether the configured SMS
// sender can deliver (when it implements SMSHealthChecker) and records the
// verdict that gates phone flows via SMSAvailable. Every call re-records, so
// hosts register it as an optional dependency probe rather than calling it
// once at boot: a failure disables phone flows (503) and the next passing
// probe re-arms them. Without a sender, or one that cannot self-check, it
// records healthy.
func (s *engine) CheckSMSHealth(ctx context.Context) error {
	if s == nil {
		return nil
	}
	checker, ok := s.sms.(SMSHealthChecker)
	if s.sms == nil || !ok {
		s.smsHealth.record(nil)
		return nil
	}
	err := checker.CheckHealth(ctx)
	s.smsHealth.record(err)
	return err
}

// SMSHealthy reports the latest CheckSMSHealth verdict; true until a check fails.
func (s *engine) SMSHealthy() bool { return s != nil && s.smsHealth.available() }

// SMSAvailable reports whether phone-based flows should be offered: a sender is
// configured and the latest health check (if any) passed.
func (s *engine) SMSAvailable() bool {
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
func (s *engine) ValidateVerificationConfiguration() error {
	if s == nil {
		return nil
	}
	policy := s.RegistrationVerificationPolicy()
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

// verificationSendTimeout is the per-send deadline for in-line email/SMS
// provider calls. Configurable via Registration.VerificationSendTimeout; defaults to
// 15s when unset.
func (s *engine) verificationSendTimeout() time.Duration {
	if s != nil && s.cfg.Registration.VerificationSendTimeout > 0 {
		return s.cfg.Registration.VerificationSendTimeout
	}
	return 15 * time.Second
}

// withSendTimeout runs a single email/SMS provider send under a bounded context
// so a configured-but-misconfigured/unreachable provider cannot hang the
// request that triggered it (e.g. registration verification). It is loop-safe:
// the deadline is cancelled as soon as the send returns, not at the end of the
// calling function.
func (s *engine) withSendTimeout(ctx context.Context, send func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, s.verificationSendTimeout())
	defer cancel()
	return send(ctx)
}
