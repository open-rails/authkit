// Package testoutbox defines the capturing email and SMS senders that
// authtest publishes as authtest.Outbox. It depends only on iam, so AuthKit's
// engine tests use it too.
package testoutbox

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
)

// Kind names what a message is for.
type Kind string

const (
	// Verification proves a contact: registration, a contact change, a
	// passwordless sign-in, a device-key enrollment or a factor setup
	// (Message.Purpose says which). It carries a code, a link, or both.
	Verification Kind = "verification"
	// LoginCode is a second-factor sign-in code.
	LoginCode Kind = "login_code"
	// PasswordReset carries a reset link.
	PasswordReset Kind = "password_reset"
	// AccountInvite carries an account registration invitation link.
	AccountInvite Kind = "account_invite"
	// Welcome follows a completed registration.
	Welcome Kind = "welcome"
	// ContactChanged goes to the address or number an account just replaced.
	ContactChanged Kind = "contact_changed"
	// DeviceKeyEnrolled tells an existing account a device key can sign in.
	DeviceKeyEnrolled Kind = "device_key_enrolled"
	// MFAReset tells an account the system removed its second factors.
	MFAReset Kind = "mfa_reset"
)

// Message is one email or SMS AuthKit asked the host to deliver.
type Message struct {
	Channel string `json:"channel"` // "email" or "sms"
	Kind    Kind   `json:"kind"`
	To      string `json:"to"`
	// Purpose is a Verification's iam.VerificationMessage.Purpose.
	Purpose string `json:"purpose,omitempty"`
	Code    string `json:"code,omitempty"`
	Link    string `json:"link,omitempty"`
	// Token is the "token" parameter of Link's fragment (or query).
	Token         string               `json:"token,omitempty"`
	ContactChange *iam.ContactChange   `json:"contact_change,omitempty"`
	DeviceKey     *iam.DeviceKeyNotice `json:"device_key,omitempty"`
	At            time.Time            `json:"at"`
}

// Outbox records every message in order; it is safe for concurrent use. The
// zero value is ready: wire Email() and SMS() as Deps.Email and Deps.SMS.
type Outbox struct {
	mu   sync.Mutex
	msgs []Message
}

// Email is the authkit.EmailSender that delivers into o.
func (o *Outbox) Email() EmailSender { return EmailSender{o} }

// SMS is the authkit.SMSSender that delivers into o.
func (o *Outbox) SMS() SMSSender { return SMSSender{o} }

// Messages returns the messages of kind sent to to, oldest first; an empty
// kind or to matches any.
func (o *Outbox) Messages(kind Kind, to string) []Message {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := []Message{}
	for _, m := range o.msgs {
		if (kind == "" || m.Kind == kind) && (to == "" || strings.EqualFold(m.To, to)) {
			out = append(out, m)
		}
	}
	return out
}

// Last returns the newest message of kind sent to to (an empty to matches any
// recipient). The test fails when there is none.
func (o *Outbox) Last(t testing.TB, kind Kind, to string) Message {
	t.Helper()
	msgs := o.Messages(kind, to)
	if len(msgs) == 0 {
		t.Fatalf("authtest: no %s message to %q", kind, to)
	}
	return msgs[len(msgs)-1]
}

func (o *Outbox) add(m Message) error {
	m.At = time.Now().UTC()
	m.Token = linkToken(m.Link)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.msgs = append(o.msgs, m)
	return nil
}

func linkToken(link string) string {
	u, err := url.Parse(link)
	if link == "" || err != nil {
		return ""
	}
	if q, err := url.ParseQuery(u.Fragment); err == nil && q.Get("token") != "" {
		return q.Get("token")
	}
	return u.Query().Get("token")
}

// EmailSender delivers email into its Outbox.
type EmailSender struct{ o *Outbox }

func (s EmailSender) SendVerification(_ context.Context, email, _ string, msg iam.VerificationMessage) error {
	return s.o.add(Message{Channel: "email", Kind: Verification, To: email, Purpose: msg.Purpose, Code: msg.Code, Link: msg.LinkURL})
}

func (s EmailSender) SendPasswordResetLink(_ context.Context, email, _, resetURL string) error {
	return s.o.add(Message{Channel: "email", Kind: PasswordReset, To: email, Link: resetURL})
}

func (s EmailSender) SendAccountRegistrationInvite(_ context.Context, email, inviteURL string) error {
	return s.o.add(Message{Channel: "email", Kind: AccountInvite, To: email, Link: inviteURL})
}

func (s EmailSender) SendLoginCode(_ context.Context, email, _, code string) error {
	return s.o.add(Message{Channel: "email", Kind: LoginCode, To: email, Code: code})
}

func (s EmailSender) SendWelcome(_ context.Context, email, _ string) error {
	return s.o.add(Message{Channel: "email", Kind: Welcome, To: email})
}

func (s EmailSender) SendContactChanged(_ context.Context, email, _ string, change iam.ContactChange) error {
	return s.o.add(Message{Channel: "email", Kind: ContactChanged, To: email, ContactChange: &change})
}

func (s EmailSender) SendDeviceKeyEnrolled(_ context.Context, email, _ string, notice iam.DeviceKeyNotice) error {
	return s.o.add(Message{Channel: "email", Kind: DeviceKeyEnrolled, To: email, DeviceKey: &notice})
}

func (s EmailSender) SendMFAReset(_ context.Context, email, _ string) error {
	return s.o.add(Message{Channel: "email", Kind: MFAReset, To: email})
}

// SMSSender delivers SMS into its Outbox.
type SMSSender struct{ o *Outbox }

func (s SMSSender) SendVerification(_ context.Context, phone string, msg iam.VerificationMessage) error {
	return s.o.add(Message{Channel: "sms", Kind: Verification, To: phone, Purpose: msg.Purpose, Code: msg.Code, Link: msg.LinkURL})
}

func (s SMSSender) SendPasswordResetLink(_ context.Context, phone, resetURL string) error {
	return s.o.add(Message{Channel: "sms", Kind: PasswordReset, To: phone, Link: resetURL})
}

func (s SMSSender) SendLoginCode(_ context.Context, phone, code string) error {
	return s.o.add(Message{Channel: "sms", Kind: LoginCode, To: phone, Code: code})
}

func (s SMSSender) SendContactChanged(_ context.Context, phone string, change iam.ContactChange) error {
	return s.o.add(Message{Channel: "sms", Kind: ContactChanged, To: phone, ContactChange: &change})
}
