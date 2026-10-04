package twilio

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-rails/authkit/iam"
)

type emailCopy struct {
	verifySubject   string
	verifyIntro     string
	changeIntro     string
	codeLabel       string
	verifyLinkLabel string
	resetSubject    string
	resetIntro      string
	loginSubject    string
	loginCodeLabel  string
	deviceSubject   string
	deviceIntro     string
	deviceWarning   string
	welcomeSubject  string
	welcomeBody     string
}

func emailCopyFor(language, app string) emailCopy {
	if language == "es" {
		return emailCopy{
			verifySubject:   fmt.Sprintf("Verifica tu cuenta de %s", app),
			verifyIntro:     "Usa los siguientes datos de verificacion:",
			changeIntro:     "Usa los siguientes datos para confirmar el cambio:",
			codeLabel:       "Codigo",
			verifyLinkLabel: "Enlace de verificacion",
			resetSubject:    fmt.Sprintf("Restablece tu contrasena de %s", app),
			resetIntro:      "Usa este enlace para restablecer tu contrasena:",
			loginSubject:    fmt.Sprintf("Tu codigo de inicio de sesion de %s", app),
			loginCodeLabel:  "Codigo de inicio de sesion",
			deviceSubject:   fmt.Sprintf("Nuevo dispositivo en tu cuenta de %s", app),
			deviceIntro:     fmt.Sprintf("Alguien esta iniciando sesion en tu cuenta de %s desde un dispositivo nuevo. Si eres tu, introduce este codigo:", app),
			deviceWarning:   "Si no eres tu, no compartas el codigo y cambia tu contrasena: quien lo intenta la conoce.",
			welcomeSubject:  fmt.Sprintf("Bienvenido a %s", app),
			welcomeBody:     fmt.Sprintf("Bienvenido a %s.", app),
		}
	}
	return emailCopy{
		verifySubject:   fmt.Sprintf("Verify your %s account", app),
		verifyIntro:     "Use the following verification details:",
		changeIntro:     "Use the following details to confirm this change:",
		codeLabel:       "Code",
		verifyLinkLabel: "Verify link",
		resetSubject:    fmt.Sprintf("Reset your %s password", app),
		resetIntro:      "Use this link to reset your password:",
		loginSubject:    fmt.Sprintf("Your %s login code", app),
		loginCodeLabel:  "Login code",
		deviceSubject:   fmt.Sprintf("New device signing in to your %s account", app),
		deviceIntro:     fmt.Sprintf("Someone is signing in to your %s account from a new device. If it's you, enter this code:", app),
		deviceWarning:   "If it isn't you, don't share the code, and change your password: whoever is trying knows it.",
		welcomeSubject:  fmt.Sprintf("Welcome to %s", app),
		welcomeBody:     fmt.Sprintf("Welcome to %s.", app),
	}
}

// emailTemplate is the built-in content for msg.Kind.
func emailTemplate(app string, msg iam.EmailMessage) (EmailContent, error) {
	c := emailCopyFor(msg.Language, app)
	switch msg.Kind {
	case iam.MessageVerification:
		return verificationEmail(c, msg), nil
	case iam.MessageLoginCode:
		code := strings.TrimSpace(msg.Code)
		return EmailContent{
			Subject:    c.loginSubject,
			Text:       c.loginCodeLabel + ": " + code,
			HTML:       "<p><strong>" + escapeHTML(c.loginCodeLabel) + ":</strong> " + escapeHTML(code) + "</p>",
			Categories: []string{"auth", "2fa-login"},
		}, nil
	case iam.MessageNewDeviceCode:
		code := strings.TrimSpace(msg.Code)
		return EmailContent{
			Subject:    c.deviceSubject,
			Text:       c.deviceIntro + "\n" + code + "\n" + c.deviceWarning,
			HTML:       "<p>" + escapeHTML(c.deviceIntro) + "</p><p><strong>" + escapeHTML(code) + "</strong></p><p>" + escapeHTML(c.deviceWarning) + "</p>",
			Categories: []string{"auth", "new-device"},
		}, nil
	case iam.MessagePasswordReset:
		return linkEmail(c.resetSubject, c.resetIntro, msg.Link, "password-reset"), nil
	case iam.MessageInvite:
		intro := fmt.Sprintf("You've been invited to join %s. Follow the link to create your account:", app)
		return linkEmail(fmt.Sprintf("You're invited to %s", app), intro, msg.Link, "invite"), nil
	case iam.MessageWelcome:
		return noticeEmail(c.welcomeSubject, c.welcomeBody, "welcome"), nil
	case iam.MessageContactChanged:
		ch := msg.ContactChange
		if ch == nil {
			return EmailContent{}, errors.New("contact_changed email needs a ContactChange")
		}
		return noticeEmail(
			fmt.Sprintf("Your %s %s was changed", app, ch.Field),
			fmt.Sprintf("The %s on your %s account was changed to %s. If this was not you, secure your account now.", ch.Field, app, ch.NewValue),
			"contact-changed",
		), nil
	case iam.MessageDeviceKeyEnrolled:
		key := msg.DeviceKey
		if key == nil {
			return EmailContent{}, errors.New("device_key_enrolled email needs a DeviceKey")
		}
		device := strings.TrimSpace(key.Label)
		if device == "" {
			device = "a new device"
		}
		return noticeEmail(
			fmt.Sprintf("A new device can sign in to your %s account", app),
			fmt.Sprintf("%s was enrolled on your %s account on %s and can now sign in as you. If this was not you, revoke it and secure your email now.", device, app, key.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")),
			"device-key-enrolled",
		), nil
	case iam.MessageMFAReset:
		return noticeEmail(
			fmt.Sprintf("Two-step verification on your %s account was reset", app),
			fmt.Sprintf("An administrator removed the passkeys, second factors, backup codes and device keys of your %s account and signed it out everywhere. Set up two-step verification again when you next sign in. If you did not ask for this, contact support now.", app),
			"mfa-reset",
		), nil
	}
	return EmailContent{}, fmt.Errorf("twilio email: no built-in template for message kind %q", msg.Kind)
}

func verificationEmail(c emailCopy, msg iam.EmailMessage) EmailContent {
	intro := c.verifyIntro
	if msg.Purpose == iam.PurposeContactChange {
		intro = c.changeIntro
	}
	code, link := strings.TrimSpace(msg.Code), strings.TrimSpace(msg.Link)
	lines := []string{intro}
	html := "<p>" + escapeHTML(intro) + "</p><ul>"
	if code != "" {
		lines = append(lines, c.codeLabel+": "+code)
		html += "<li><strong>" + escapeHTML(c.codeLabel) + ":</strong> " + escapeHTML(code) + "</li>"
	}
	if link != "" {
		lines = append(lines, c.verifyLinkLabel+": "+link)
		html += "<li><strong>" + escapeHTML(c.verifyLinkLabel) + ":</strong> " + escapeHTML(link) + "</li>"
	}
	html += "</ul>"
	return EmailContent{
		Subject:    c.verifySubject,
		Text:       strings.Join(lines, "\n"),
		HTML:       html,
		Categories: []string{"auth", "email-verification"},
	}
}

func linkEmail(subject, intro, link, category string) EmailContent {
	link = strings.TrimSpace(link)
	return EmailContent{
		Subject:    subject,
		Text:       intro + "\n" + link,
		HTML:       "<p>" + escapeHTML(intro) + "</p><p>" + escapeHTML(link) + "</p>",
		Categories: []string{"auth", category},
	}
}

func noticeEmail(subject, text, category string) EmailContent {
	return EmailContent{
		Subject:    subject,
		Text:       text,
		HTML:       "<p>" + escapeHTML(text) + "</p>",
		Categories: []string{"auth", category},
	}
}

var htmlEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	"\"", "&quot;",
	"'", "&#39;",
)

func escapeHTML(v string) string { return htmlEscaper.Replace(v) }
