package harness

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/open-rails/authkit/embedded"
)

// Message is one captured email/SMS delivery.
type Message struct {
	Channel string    `json:"channel"`
	To      string    `json:"to"`
	Kind    string    `json:"kind"`
	Purpose string    `json:"purpose,omitempty"`
	Code    string    `json:"code,omitempty"`
	Link    string    `json:"link,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	At      time.Time `json:"at"`
}

// Outbox records every delivery in order; tests read it instead of a mailbox.
type Outbox struct {
	mu   sync.Mutex
	msgs []Message
}

func (o *Outbox) add(m Message) error {
	m.At = time.Now().UTC()
	o.mu.Lock()
	o.msgs = append(o.msgs, m)
	o.mu.Unlock()
	return nil
}

// List returns messages, filtered by recipient when to is non-empty.
func (o *Outbox) List(to string) []Message {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := []Message{}
	for _, m := range o.msgs {
		if to == "" || strings.EqualFold(m.To, to) {
			out = append(out, m)
		}
	}
	return out
}

type emailSender struct{ o *Outbox }

func (s emailSender) SendVerification(_ context.Context, email, _ string, msg embedded.VerificationMessage) error {
	return s.o.add(Message{Channel: "email", To: email, Kind: "verification", Purpose: msg.Purpose, Code: msg.Code, Link: msg.LinkURL})
}
func (s emailSender) SendPasswordResetLink(_ context.Context, email, _, url string) error {
	return s.o.add(Message{Channel: "email", To: email, Kind: "password_reset", Link: url})
}
func (s emailSender) SendAccountRegistrationInvite(_ context.Context, email, url string) error {
	return s.o.add(Message{Channel: "email", To: email, Kind: "registration_invite", Link: url})
}
func (s emailSender) SendLoginCode(_ context.Context, email, _, code string) error {
	return s.o.add(Message{Channel: "email", To: email, Kind: "login_code", Code: code})
}
func (s emailSender) SendWelcome(_ context.Context, email, _ string) error {
	return s.o.add(Message{Channel: "email", To: email, Kind: "welcome"})
}
func (s emailSender) SendContactChanged(_ context.Context, email, _ string, c embedded.ContactChange) error {
	return s.o.add(Message{Channel: "email", To: email, Kind: "contact_changed", Detail: c.Field + ":" + c.NewValue})
}
func (s emailSender) SendDeviceKeyEnrolled(_ context.Context, email, _ string, n embedded.DeviceKeyNotice) error {
	return s.o.add(Message{Channel: "email", To: email, Kind: "device_key_enrolled", Detail: n.Label})
}

type smsSender struct{ o *Outbox }

func (s smsSender) SendVerification(_ context.Context, phone string, msg embedded.VerificationMessage) error {
	return s.o.add(Message{Channel: "sms", To: phone, Kind: "verification", Purpose: msg.Purpose, Code: msg.Code, Link: msg.LinkURL})
}
func (s smsSender) SendPasswordResetLink(_ context.Context, phone, url string) error {
	return s.o.add(Message{Channel: "sms", To: phone, Kind: "password_reset", Link: url})
}
func (s smsSender) SendLoginCode(_ context.Context, phone, code string) error {
	return s.o.add(Message{Channel: "sms", To: phone, Kind: "login_code", Code: code})
}
func (s smsSender) SendContactChanged(_ context.Context, phone string, c embedded.ContactChange) error {
	return s.o.add(Message{Channel: "sms", To: phone, Kind: "contact_changed", Detail: c.Field + ":" + c.NewValue})
}
