// Package logsender delivers AuthKit's email and text messages to a log
// instead of a mailbox or phone: a development sender, so local sign-up and
// sign-in codes and links can be read from the log. Anyone reading the log
// can then sign in as those accounts: never use it in production.
//
//	authkit.Deps{Email: logsender.Email{Logger: log}, SMS: logsender.SMS{Logger: log}}
package logsender

import (
	"context"

	"log/slog"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/logx"
)

// Email logs each email at INFO on Logger (nil is slog.Default()).
type Email struct{ Logger *slog.Logger }

// Send logs msg.
func (e Email) Send(ctx context.Context, msg iam.EmailMessage) error {
	logx.Or(e.Logger).InfoContext(ctx, "authkit: email (development log sender)", "kind", msg.Kind, "to", msg.To, "code", msg.Code, "link", msg.Link)
	return nil
}

// CheckHealth is always healthy.
func (Email) CheckHealth(context.Context) error { return nil }

// SMS logs each text message at INFO on Logger (nil is slog.Default()).
type SMS struct{ Logger *slog.Logger }

// Send logs msg.
func (s SMS) Send(ctx context.Context, msg iam.SMSMessage) error {
	logx.Or(s.Logger).InfoContext(ctx, "authkit: text message (development log sender)", "kind", msg.Kind, "to", msg.To, "code", msg.Code, "link", msg.Link)
	return nil
}

// CheckHealth is always healthy.
func (SMS) CheckHealth(context.Context) error { return nil }
