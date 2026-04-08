package emailtwilio

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

// Sender sends emails through Twilio Email API (SendGrid endpoint).
type Sender struct {
	APIKey    string
	FromEmail string
	FromName  string
	AppName   string
	Client    *http.Client

	VerificationLinkURL func(token string) string
	ResetLinkURL        func(token string) string
}

func New(apiKey, fromEmail, fromName, appName string) *Sender {
	return &Sender{
		APIKey:    strings.TrimSpace(apiKey),
		FromEmail: strings.TrimSpace(fromEmail),
		FromName:  strings.TrimSpace(fromName),
		AppName:   strings.TrimSpace(appName),
	}
}

func (s *Sender) httpClient() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (s *Sender) SendVerification(ctx context.Context, email, username string, msg core.VerificationMessage) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	app := s.appLabel()
	subject := fmt.Sprintf("Verify your %s account", app)

	lines := []string{"Use the following verification details:"}
	if strings.TrimSpace(msg.Code) != "" {
		lines = append(lines, "Code: "+strings.TrimSpace(msg.Code))
	}
	if strings.TrimSpace(msg.LinkToken) != "" {
		linkOrToken := strings.TrimSpace(msg.LinkToken)
		if s.VerificationLinkURL != nil {
			if built := strings.TrimSpace(s.VerificationLinkURL(linkOrToken)); built != "" {
				linkOrToken = built
			}
		}
		lines = append(lines, "Verify link: "+linkOrToken)
	}
	text := strings.Join(lines, "\n")
	html := "<p>Use the following verification details:</p><ul>"
	if strings.TrimSpace(msg.Code) != "" {
		html += "<li><strong>Code:</strong> " + escapeHTML(strings.TrimSpace(msg.Code)) + "</li>"
	}
	if strings.TrimSpace(msg.LinkToken) != "" {
		linkOrToken := strings.TrimSpace(msg.LinkToken)
		if s.VerificationLinkURL != nil {
			if built := strings.TrimSpace(s.VerificationLinkURL(linkOrToken)); built != "" {
				linkOrToken = built
			}
		}
		html += "<li><strong>Verify link:</strong> " + escapeHTML(linkOrToken) + "</li>"
	}
	html += "</ul>"
	return s.sendEmail(ctx, email, subject, text, html)
}

func (s *Sender) SendPasswordResetLink(ctx context.Context, email, username, token string) error {
	app := s.appLabel()
	subject := fmt.Sprintf("Reset your %s password", app)
	linkOrToken := strings.TrimSpace(token)
	if s.ResetLinkURL != nil {
		if built := strings.TrimSpace(s.ResetLinkURL(linkOrToken)); built != "" {
			linkOrToken = built
		}
	}
	text := fmt.Sprintf("Use this link to reset your password:\n%s", linkOrToken)
	html := fmt.Sprintf("<p>Use this link to reset your password:</p><p>%s</p>", escapeHTML(linkOrToken))
	return s.sendEmail(ctx, email, subject, text, html)
}

func (s *Sender) SendLoginCode(ctx context.Context, email, username, code string) error {
	app := s.appLabel()
	subject := fmt.Sprintf("Your %s login code", app)
	trimmedCode := strings.TrimSpace(code)
	text := fmt.Sprintf("Login code: %s", trimmedCode)
	html := fmt.Sprintf("<p><strong>Login code:</strong> %s</p>", escapeHTML(trimmedCode))
	return s.sendEmail(ctx, email, subject, text, html)
}

func (s *Sender) SendWelcome(ctx context.Context, email, username string) error {
	app := s.appLabel()
	subject := fmt.Sprintf("Welcome to %s", app)
	text := fmt.Sprintf("Welcome to %s.", app)
	html := fmt.Sprintf("<p>Welcome to %s.</p>", escapeHTML(app))
	return s.sendEmail(ctx, email, subject, text, html)
}

func (s *Sender) appLabel() string {
	if strings.TrimSpace(s.AppName) != "" {
		return strings.TrimSpace(s.AppName)
	}
	return "Auth"
}

func (s *Sender) sendEmail(ctx context.Context, to, subject, textBody, htmlBody string) error {
	if s == nil {
		return fmt.Errorf("email sender is nil")
	}
	if strings.TrimSpace(s.APIKey) == "" {
		return fmt.Errorf("twilio email API key is required")
	}
	if strings.TrimSpace(s.FromEmail) == "" {
		return fmt.Errorf("from email is required")
	}
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("recipient email is required")
	}

	payload := map[string]any{
		"personalizations": []map[string]any{{
			"to":      []map[string]string{{"email": strings.TrimSpace(to)}},
			"subject": subject,
		}},
		"from": map[string]string{
			"email": strings.TrimSpace(s.FromEmail),
			"name":  strings.TrimSpace(s.FromName),
		},
		"content": []map[string]string{
			{"type": "text/plain", "value": textBody},
			{"type": "text/html", "value": htmlBody},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.sendgrid.com/v3/mail/send", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(s.APIKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("twilio email API error: status %d", resp.StatusCode)
}

func escapeHTML(v string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(v)
}
