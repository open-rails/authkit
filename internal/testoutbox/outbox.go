// Package testoutbox defines the capturing email and SMS senders that
// authtest publishes as authtest.Outbox. It depends only on iam and config,
// so AuthKit's engine tests use it too.
package testoutbox

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
)

// Message is one email or SMS AuthKit asked the host to deliver.
type Message struct {
	Channel  string                  `json:"channel"` // "email" or "sms"
	Kind     iam.MessageKind         `json:"kind"`
	To       string                  `json:"to"`
	Language string                  `json:"language"`
	Purpose  iam.VerificationPurpose `json:"purpose,omitempty"`
	Code     string                  `json:"code,omitempty"`
	Link     string                  `json:"link,omitempty"`
	// Token is the "token" parameter of Link's fragment (or query).
	Token         string               `json:"token,omitempty"`
	ContactChange *iam.ContactChange   `json:"contact_change,omitempty"`
	DeviceKey     *iam.DeviceKeyNotice `json:"device_key,omitempty"`
	// UserID and Domain are an SMS's account and the origin its code is
	// bound to (iam.SMSMessage).
	UserID string    `json:"user_id,omitempty"`
	Domain string    `json:"domain,omitempty"`
	At     time.Time `json:"at"`
}

// Outbox records every message in order; it is safe for concurrent use. The
// zero value is ready: wire Email() and SMS() as Deps.Email and Deps.SMS.
type Outbox struct {
	mu        sync.Mutex
	msgs      []Message
	emailDown error
	smsDown   error
}

// Email is o as Deps.Email: it delivers into o, and its CheckHealth returns
// what SetEmailHealth set.
func (o *Outbox) Email() config.EmailSender { return emailSender{o} }

// SMS is Email for Deps.SMS and SetSMSHealth.
func (o *Outbox) SMS() config.SMSSender { return smsSender{o} }

// Of is the Outbox behind a sender Email or SMS returned, else nil.
func Of(sender any) *Outbox {
	switch s := sender.(type) {
	case emailSender:
		return s.o
	case smsSender:
		return s.o
	}
	return nil
}

// SetEmailHealth sets what the email sender's CheckHealth returns; nil, the
// default, is healthy.
func (o *Outbox) SetEmailHealth(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.emailDown = err
}

// SetSMSHealth is SetEmailHealth for the SMS sender.
func (o *Outbox) SetSMSHealth(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.smsDown = err
}

type emailSender struct{ o *Outbox }

func (s emailSender) Send(_ context.Context, m iam.EmailMessage) error {
	return s.o.add(Message{Channel: "email", Kind: m.Kind, To: m.To, Language: m.Language, Purpose: m.Purpose,
		Code: m.Code, Link: m.Link, ContactChange: m.ContactChange, DeviceKey: m.DeviceKey})
}

func (s emailSender) CheckHealth(context.Context) error {
	s.o.mu.Lock()
	defer s.o.mu.Unlock()
	return s.o.emailDown
}

type smsSender struct{ o *Outbox }

func (s smsSender) Send(_ context.Context, m iam.SMSMessage) error {
	return s.o.add(Message{Channel: "sms", Kind: m.Kind, To: m.To, Language: m.Language, Purpose: m.Purpose,
		Code: m.Code, Link: m.Link, ContactChange: m.ContactChange, UserID: m.UserID, Domain: m.Domain})
}

func (s smsSender) CheckHealth(context.Context) error {
	s.o.mu.Lock()
	defer s.o.mu.Unlock()
	return s.o.smsDown
}

// Messages returns the messages of kind sent to to, oldest first; an empty
// kind or to matches any.
func (o *Outbox) Messages(kind iam.MessageKind, to string) []Message {
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
func (o *Outbox) Last(t testing.TB, kind iam.MessageKind, to string) Message {
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
