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
	"errors"
	"net/http"
	"strings"
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
