package twilio

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
	authlang "github.com/open-rails/authkit/lang"
)

const sendGridMailSendURL = "https://api.sendgrid.com/v3/mail/send"

// Message is the rendered email payload sent by Sender.
type Message struct {
	Subject    string
	TextBody   string
	HTMLBody   string
	Categories []string
	CustomArgs map[string]string
}

// VerificationBuilder renders a verification email.
type VerificationBuilder func(ctx context.Context, email, username string, msg core.VerificationMessage) Message

// PasswordResetBuilder renders a password reset email.
type PasswordResetBuilder func(ctx context.Context, email, username, resetURL string) Message

// LoginCodeBuilder renders a login code email.
type LoginCodeBuilder func(ctx context.Context, email, username, code string) Message

// WelcomeBuilder renders a welcome email.
type WelcomeBuilder func(ctx context.Context, email, username string) Message

// Config configures the Twilio Email API / SendGrid Mail Send adapter.
type Config struct {
	APIKey    string
	FromEmail string
	FromName  string
	AppName   string
	Client    *http.Client

	Categories []string
	CustomArgs map[string]string

	VerificationBuilder  VerificationBuilder
	PasswordResetBuilder PasswordResetBuilder
	LoginCodeBuilder     LoginCodeBuilder
	WelcomeBuilder       WelcomeBuilder
}

// Sender sends emails through Twilio Email API (SendGrid endpoint).
type Sender struct {
	APIKey    string
	FromEmail string
	FromName  string
	AppName   string
	Client    *http.Client

	Categories []string
	CustomArgs map[string]string

	VerificationBuilder  VerificationBuilder
	PasswordResetBuilder PasswordResetBuilder
	LoginCodeBuilder     LoginCodeBuilder
	WelcomeBuilder       WelcomeBuilder
}

// New creates a validated Sender.
func New(cfg Config) (*Sender, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	fromEmail := strings.TrimSpace(cfg.FromEmail)
	if apiKey == "" {
		return nil, fmt.Errorf("twilio email API key is required")
	}
	if fromEmail == "" {
		return nil, fmt.Errorf("from email is required")
	}
	return &Sender{
		APIKey:               apiKey,
		FromEmail:            fromEmail,
		FromName:             strings.TrimSpace(cfg.FromName),
		AppName:              strings.TrimSpace(cfg.AppName),
		Client:               cfg.Client,
		Categories:           compactStrings(cfg.Categories),
		CustomArgs:           compactStringMap(cfg.CustomArgs),
		VerificationBuilder:  cfg.VerificationBuilder,
		PasswordResetBuilder: cfg.PasswordResetBuilder,
		LoginCodeBuilder:     cfg.LoginCodeBuilder,
		WelcomeBuilder:       cfg.WelcomeBuilder,
	}, nil
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
	if s.VerificationBuilder != nil {
		return s.sendEmail(ctx, email, s.VerificationBuilder(ctx, email, username, msg))
	}
	return s.sendEmail(ctx, email, defaultVerificationMessage(ctx, s.appLabel(), msg))
}

type defaultCopy struct {
	verifySubject   string
	verifyIntro     string
	codeLabel       string
	verifyLinkLabel string
	resetSubject    string
	resetIntro      string
	loginSubject    string
	loginCodeLabel  string
	welcomeSubject  string
	welcomeBody     string
	welcomeBodyHTML string
}

func copyForContext(ctx context.Context, app string) defaultCopy {
	switch contextLanguage(ctx) {
	case "es":
		return defaultCopy{
			verifySubject:   fmt.Sprintf("Verifica tu cuenta de %s", app),
			verifyIntro:     "Usa los siguientes datos de verificacion:",
			codeLabel:       "Codigo",
			verifyLinkLabel: "Enlace de verificacion",
			resetSubject:    fmt.Sprintf("Restablece tu contrasena de %s", app),
			resetIntro:      "Usa este enlace para restablecer tu contrasena:",
			loginSubject:    fmt.Sprintf("Tu codigo de inicio de sesion de %s", app),
			loginCodeLabel:  "Codigo de inicio de sesion",
			welcomeSubject:  fmt.Sprintf("Bienvenido a %s", app),
			welcomeBody:     fmt.Sprintf("Bienvenido a %s.", app),
			welcomeBodyHTML: fmt.Sprintf("Bienvenido a %s.", app),
		}
	default:
		return defaultCopy{
			verifySubject:   fmt.Sprintf("Verify your %s account", app),
			verifyIntro:     "Use the following verification details:",
			codeLabel:       "Code",
			verifyLinkLabel: "Verify link",
			resetSubject:    fmt.Sprintf("Reset your %s password", app),
			resetIntro:      "Use this link to reset your password:",
			loginSubject:    fmt.Sprintf("Your %s login code", app),
			loginCodeLabel:  "Login code",
			welcomeSubject:  fmt.Sprintf("Welcome to %s", app),
			welcomeBody:     fmt.Sprintf("Welcome to %s.", app),
			welcomeBodyHTML: fmt.Sprintf("Welcome to %s.", app),
		}
	}
}

func contextLanguage(ctx context.Context) string {
	language, ok := authlang.LanguageFromContext(ctx)
	if !ok {
		return "en"
	}
	language = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(language, "_", "-")))
	if language == "" {
		return "en"
	}
	if i := strings.Index(language, "-"); i > 0 {
		language = language[:i]
	}
	switch language {
	case "es":
		return "es"
	default:
		return "en"
	}
}

func defaultVerificationMessage(ctx context.Context, app string, msg core.VerificationMessage) Message {
	copy := copyForContext(ctx, app)
	lines := []string{copy.verifyIntro}
	if strings.TrimSpace(msg.Code) != "" {
		lines = append(lines, copy.codeLabel+": "+strings.TrimSpace(msg.Code))
	}
	if strings.TrimSpace(msg.LinkURL) != "" {
		lines = append(lines, copy.verifyLinkLabel+": "+strings.TrimSpace(msg.LinkURL))
	}
	html := "<p>" + escapeHTML(copy.verifyIntro) + "</p><ul>"
	if strings.TrimSpace(msg.Code) != "" {
		html += "<li><strong>" + escapeHTML(copy.codeLabel) + ":</strong> " + escapeHTML(strings.TrimSpace(msg.Code)) + "</li>"
	}
	if strings.TrimSpace(msg.LinkURL) != "" {
		html += "<li><strong>" + escapeHTML(copy.verifyLinkLabel) + ":</strong> " + escapeHTML(strings.TrimSpace(msg.LinkURL)) + "</li>"
	}
	html += "</ul>"
	return Message{Subject: copy.verifySubject, TextBody: strings.Join(lines, "\n"), HTMLBody: html, Categories: []string{"auth", "email-verification"}}
}

func (s *Sender) SendPasswordResetLink(ctx context.Context, email, username, resetURL string) error {
	app := s.appLabel()
	resetURL = strings.TrimSpace(resetURL)
	if s.PasswordResetBuilder != nil {
		return s.sendEmail(ctx, email, s.PasswordResetBuilder(ctx, email, username, resetURL))
	}
	copy := copyForContext(ctx, app)
	text := fmt.Sprintf("%s\n%s", copy.resetIntro, resetURL)
	html := fmt.Sprintf("<p>%s</p><p>%s</p>", escapeHTML(copy.resetIntro), escapeHTML(resetURL))
	return s.sendEmail(ctx, email, Message{Subject: copy.resetSubject, TextBody: text, HTMLBody: html, Categories: []string{"auth", "password-reset"}})
}

func (s *Sender) SendLoginCode(ctx context.Context, email, username, code string) error {
	if s.LoginCodeBuilder != nil {
		return s.sendEmail(ctx, email, s.LoginCodeBuilder(ctx, email, username, code))
	}
	app := s.appLabel()
	copy := copyForContext(ctx, app)
	trimmedCode := strings.TrimSpace(code)
	text := fmt.Sprintf("%s: %s", copy.loginCodeLabel, trimmedCode)
	html := fmt.Sprintf("<p><strong>%s:</strong> %s</p>", escapeHTML(copy.loginCodeLabel), escapeHTML(trimmedCode))
	return s.sendEmail(ctx, email, Message{Subject: copy.loginSubject, TextBody: text, HTMLBody: html, Categories: []string{"auth", "2fa-login"}})
}

func (s *Sender) SendWelcome(ctx context.Context, email, username string) error {
	if s.WelcomeBuilder != nil {
		return s.sendEmail(ctx, email, s.WelcomeBuilder(ctx, email, username))
	}
	app := s.appLabel()
	copy := copyForContext(ctx, app)
	html := fmt.Sprintf("<p>%s</p>", escapeHTML(copy.welcomeBodyHTML))
	return s.sendEmail(ctx, email, Message{Subject: copy.welcomeSubject, TextBody: copy.welcomeBody, HTMLBody: html, Categories: []string{"auth", "welcome"}})
}

func (s *Sender) appLabel() string {
	if strings.TrimSpace(s.AppName) != "" {
		return strings.TrimSpace(s.AppName)
	}
	return "Auth"
}

func (s *Sender) sendEmail(ctx context.Context, to string, msg Message) error {
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
	if strings.TrimSpace(msg.Subject) == "" {
		return fmt.Errorf("email subject is required")
	}
	if strings.TrimSpace(msg.TextBody) == "" && strings.TrimSpace(msg.HTMLBody) == "" {
		return fmt.Errorf("email body is required")
	}

	payload := map[string]any{
		"personalizations": []map[string]any{{
			"to":      []map[string]string{{"email": strings.TrimSpace(to)}},
			"subject": strings.TrimSpace(msg.Subject),
		}},
		"from": map[string]string{
			"email": strings.TrimSpace(s.FromEmail),
			"name":  strings.TrimSpace(s.FromName),
		},
	}
	content := make([]map[string]string, 0, 2)
	if strings.TrimSpace(msg.TextBody) != "" {
		content = append(content, map[string]string{"type": "text/plain", "value": msg.TextBody})
	}
	if strings.TrimSpace(msg.HTMLBody) != "" {
		content = append(content, map[string]string{"type": "text/html", "value": msg.HTMLBody})
	}
	payload["content"] = content
	if categories := mergeStrings(s.Categories, msg.Categories); len(categories) > 0 {
		payload["categories"] = categories
	}
	if customArgs := mergeStringMaps(s.CustomArgs, msg.CustomArgs); len(customArgs) > 0 {
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
