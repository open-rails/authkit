package twilio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
)

const sendGridMailSendURL = "https://api.sendgrid.com/v3/mail/send"

// EmailContent is one rendered email.
type EmailContent struct {
	Subject string
	Text    string
	HTML    string
	// Categories and CustomArgs are added to EmailConfig's.
	Categories []string
	CustomArgs map[string]string
}

// EmailConfig configures NewEmail. APIKey and FromEmail are required.
type EmailConfig struct {
	// APIKey is a Twilio SendGrid API key.
	APIKey    string
	FromEmail string
	FromName  string
	// AppName names the app in the built-in copy (default "Auth").
	AppName string
	// Client sends the API requests (default: a 10s-timeout client).
	Client *http.Client
	// Categories and CustomArgs tag every email.
	Categories []string
	CustomArgs map[string]string
	// Render returns the content for msg, or false to use the built-in
	// template for msg.Kind.
	Render func(ctx context.Context, msg iam.EmailMessage) (EmailContent, bool)
}

// Email delivers AuthKit's emails through the Twilio SendGrid Mail Send API.
// It is an authkit.EmailSender: wire it as authkit.Deps.Email.
type Email struct {
	apiKey     string
	fromEmail  string
	fromName   string
	app        string
	client     *http.Client
	categories []string
	customArgs map[string]string
	render     func(context.Context, iam.EmailMessage) (EmailContent, bool)
}

// NewEmail validates cfg and returns an Email.
func NewEmail(cfg EmailConfig) (*Email, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		return nil, errors.New("twilio email API key is required")
	}
	fromEmail := strings.TrimSpace(cfg.FromEmail)
	if fromEmail == "" {
		return nil, errors.New("from email is required")
	}
	return &Email{
		apiKey:     apiKey,
		fromEmail:  fromEmail,
		fromName:   strings.TrimSpace(cfg.FromName),
		app:        appLabel(cfg.AppName),
		client:     httpClient(cfg.Client),
		categories: compactStrings(cfg.Categories),
		customArgs: compactStringMap(cfg.CustomArgs),
		render:     cfg.Render,
	}, nil
}

// Send renders msg (Render, else the built-in template for msg.Kind) and
// delivers it.
func (e *Email) Send(ctx context.Context, msg iam.EmailMessage) error {
	to := strings.TrimSpace(msg.To)
	if to == "" {
		return errors.New("recipient email is required")
	}
	if msg.Kind == iam.MessageVerification {
		if err := validateVerification(msg.Code, msg.Link); err != nil {
			return err
		}
	}
	var (
		content EmailContent
		ok      bool
	)
	if e.render != nil {
		content, ok = e.render(ctx, msg)
	}
	if !ok {
		var err error
		if content, err = emailTemplate(e.app, msg); err != nil {
			return err
		}
	}
	return e.deliver(ctx, to, content)
}

func (e *Email) deliver(ctx context.Context, to string, c EmailContent) error {
	if strings.TrimSpace(c.Subject) == "" {
		return errors.New("email subject is required")
	}
	if strings.TrimSpace(c.Text) == "" && strings.TrimSpace(c.HTML) == "" {
		return errors.New("email body is required")
	}

	payload := map[string]any{
		"personalizations": []map[string]any{{
			"to":      []map[string]string{{"email": to}},
			"subject": strings.TrimSpace(c.Subject),
		}},
		"from": map[string]string{
			"email": e.fromEmail,
			"name":  e.fromName,
		},
	}
	content := make([]map[string]string, 0, 2)
	if strings.TrimSpace(c.Text) != "" {
		content = append(content, map[string]string{"type": "text/plain", "value": c.Text})
	}
	if strings.TrimSpace(c.HTML) != "" {
		content = append(content, map[string]string{"type": "text/html", "value": c.HTML})
	}
	payload["content"] = content
	if categories := mergeStrings(e.categories, c.Categories); len(categories) > 0 {
		payload["categories"] = categories
	}
	if customArgs := mergeStringMaps(e.customArgs, c.CustomArgs); len(customArgs) > 0 {
		payload["custom_args"] = customArgs
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sendGridMailSendURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+e.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("twilio email API error: status %d", resp.StatusCode)
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func mergeStrings(a, b []string) []string {
	return compactStrings(append(append([]string{}, a...), b...))
}

func compactStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for k, v := range values {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k != "" && v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeStringMaps(a, b map[string]string) map[string]string {
	out := compactStringMap(a)
	if out == nil {
		out = map[string]string{}
	}
	for k, v := range compactStringMap(b) {
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
