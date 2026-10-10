// Package smtp delivers AuthKit's email through any SMTP server, so the
// provider is configuration: SendGrid (smtp.sendgrid.net, username "apikey",
// an API key as the password), ZeptoMail, SES or a server of your own.
//
//	email, err := smtp.New(smtp.Config{
//		Server: smtp.Server{
//			Host:     os.Getenv("EMAIL_SMTP_HOST"),
//			Port:     587,
//			Username: os.Getenv("EMAIL_SMTP_USERNAME"),
//			Password: os.Getenv("EMAIL_SMTP_PASSWORD"),
//			From:     "MyApp <hello@myapp.com>",
//		},
//		AppName: "MyApp",
//	})
//	if err != nil {
//		return err
//	}
//	deps := authkit.Deps{Postgres: db, Email: email}
//
// Each message kind renders from a built-in template in the message's
// Language (Spanish for "es", else English). Set Render to supply your own
// content for some kinds; returning false falls back to the built-in one.
package smtp

import (
	"context"
	"errors"
	"strings"

	"github.com/open-rails/authkit/iam"
	mailer "github.com/open-rails/helpers/smtp"
)

// Server is the SMTP server and sender (helpers/smtp.Config): Host, Port
// (465 implicit TLS, else STARTTLS; 0 is 587), Username, Password and From,
// one RFC 5322 mailbox such as "MyApp <hello@myapp.com>".
type Server = mailer.Config

// Content is one rendered email: a subject and a text or HTML body, or both.
type Content struct {
	Subject string
	Text    string
	HTML    string
}

// Config configures New. Server.Host and Server.From are required.
type Config struct {
	Server Server
	// AppName names the app in the built-in copy (default "Auth").
	AppName string
	// Render returns the content for msg, or false to use the built-in
	// template for msg.Kind.
	Render func(ctx context.Context, msg iam.EmailMessage) (Content, bool)
}

// Email is an authkit.EmailSender: wire it as authkit.Deps.Email.
type Email struct {
	sender *mailer.Sender
	app    string
	render func(context.Context, iam.EmailMessage) (Content, bool)
}

// New validates cfg and returns an Email. It does not connect; Start's health
// probe does.
func New(cfg Config) (*Email, error) {
	if strings.TrimSpace(cfg.Server.From) == "" {
		return nil, errors.New("smtp: from is required")
	}
	sender, err := mailer.New(cfg.Server)
	if err != nil {
		return nil, err
	}
	app := strings.TrimSpace(cfg.AppName)
	if app == "" {
		app = "Auth"
	}
	return &Email{sender: sender, app: app, render: cfg.Render}, nil
}

// Send renders msg (Render, else the built-in template for msg.Kind) and
// delivers it.
func (e *Email) Send(ctx context.Context, msg iam.EmailMessage) error {
	to := strings.TrimSpace(msg.To)
	if to == "" {
		return errors.New("smtp: recipient email is required")
	}
	if msg.Kind == iam.MessageVerification && strings.TrimSpace(msg.Code) == "" && strings.TrimSpace(msg.Link) == "" {
		return errors.New("smtp: verification message must contain a code or a link")
	}
	var (
		content Content
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
	return e.sender.Send(ctx, mailer.Message{To: to, Subject: content.Subject, Text: content.Text, HTML: content.HTML})
}

// CheckHealth connects, negotiates TLS and authenticates without sending:
// an error when the server is unreachable or refuses the credentials.
func (e *Email) CheckHealth(ctx context.Context) error {
	return e.sender.CheckHealth(ctx)
}
