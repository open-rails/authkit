// Package twilio delivers AuthKit's emails through Twilio SendGrid and its text
// messages through Twilio Messaging.
//
//	email, err := twilio.NewEmail(twilio.EmailConfig{
//		APIKey:    os.Getenv("SENDGRID_API_KEY"),
//		FromEmail: "hello@myapp.com",
//		AppName:   "MyApp",
//	})
//	if err != nil {
//		return err
//	}
//	sms, err := twilio.NewSMS(twilio.SMSConfig{
//		AccountSID:          os.Getenv("TWILIO_ACCOUNT_SID"),
//		AuthToken:           os.Getenv("TWILIO_AUTH_TOKEN"),
//		MessagingServiceSID: os.Getenv("TWILIO_MESSAGING_SERVICE_SID"),
//		AppName:             "MyApp",
//	})
//	if err != nil {
//		return err
//	}
//	deps := authkit.Deps{Postgres: db, Email: email, SMS: sms}
//
// Each sender renders every message kind from a built-in template in the
// message's Language (Spanish for "es", else English). Set Render to supply your
// own content for some kinds; returning false falls back to the built-in one.
package twilio

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

func appLabel(name string) string {
	if n := strings.TrimSpace(name); n != "" {
		return n
	}
	return "Auth"
}

func httpClient(custom *http.Client) *http.Client {
	if custom != nil {
		return custom
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func validateVerification(code, link string) error {
	if strings.TrimSpace(code) == "" && strings.TrimSpace(link) == "" {
		return errors.New("verification message must contain a code or a link")
	}
	return nil
}

// changeWarner logs a health warning once per change of its state.
type changeWarner struct {
	mu   sync.Mutex
	last string
}

// warn records state and logs msg when state is new and not "".
func (w *changeWarner) warn(ctx context.Context, state, msg string, args ...any) {
	w.mu.Lock()
	changed := state != w.last
	w.last = state
	w.mu.Unlock()
	if changed && state != "" {
		slog.WarnContext(ctx, msg, args...)
	}
}

// reset forgets the state, so its next warning logs again.
func (w *changeWarner) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.last = ""
}
