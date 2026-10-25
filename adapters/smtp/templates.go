package smtp

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-rails/authkit/iam"
)

// emailCopy is the built-in wording in one language; {app}, {field},
// {value}, {device} and {date} are filled in.
type emailCopy struct {
	verify, change, twoFactor, login, reset, invite, exists action

	deviceSubject, deviceIntro, deviceWarning string
	ignore, footer                            string
	welcomeSubject, welcomeBody               string
	changedSubject, changedBody, email, phone string
	enrolledSubject, enrolledBody, newDevice  string
	mfaResetSubject, mfaResetBody             string
	existsNote                                string
}

// action is a message asking for one step: its subject, the line saying what
// it is for, and its link's label.
type action struct{ subject, intro, button string }

var english = emailCopy{
	verify:    action{"Verify your {app} account", "Use this code to confirm your email address for {app}.", "Verify email"},
	change:    action{"Confirm your new {app} email address", "Use this code to make this the email address of your {app} account.", "Confirm email"},
	twoFactor: action{"Your {app} verification code", "Use this code to turn on two-step verification for your {app} account.", "Verify"},
	login:     action{"Your {app} login code", "Use this code to sign in to {app}.", "Sign in"},
	reset:     action{"Reset your {app} password", "Use this link to reset your {app} password.", "Reset password"},
	invite:    action{"You're invited to {app}", "You've been invited to join {app}. Follow the link to create your account.", "Create account"},
	exists:    action{"Someone tried to use your {app} email address", "Someone just tried to use this email address for another {app} account. It already belongs to your account, so nothing was changed. If it was you, sign in with this address, or choose a new password with this link.", "Reset password"},

	deviceSubject:   "New device signing in to your {app} account",
	deviceIntro:     "Someone is signing in to your {app} account from a new device. If it's you, enter this code:",
	deviceWarning:   "If it isn't you, don't share the code, and change your password: whoever is trying knows it.",
	ignore:          "If you didn't request this, you can ignore this email.",
	footer:          "This is an automated message from {app}.",
	welcomeSubject:  "Welcome to {app}",
	welcomeBody:     "Your {app} account is ready.",
	changedSubject:  "Your {app} {field} was changed",
	changedBody:     "The {field} on your {app} account was changed to {value}. If this was not you, secure your account now.",
	email:           "email address",
	phone:           "phone number",
	enrolledSubject: "A new device can sign in to your {app} account",
	enrolledBody:    "{device} was enrolled on your {app} account on {date} and can now sign in as you. If this was not you, revoke it and secure your email now.",
	newDevice:       "A new device",
	mfaResetSubject: "Two-step verification on your {app} account was reset",
	mfaResetBody:    "An administrator removed the passkeys, second factors, backup codes and device keys of your {app} account and signed it out everywhere. Set up two-step verification again when you next sign in. If you did not ask for this, contact support now.",
	existsNote:      "If it wasn't you, you can ignore this email. Your account is unchanged.",
}

var spanish = emailCopy{
	verify:    action{"Verifica tu cuenta de {app}", "Usa este código para confirmar tu correo electrónico en {app}.", "Verificar correo"},
	change:    action{"Confirma tu nuevo correo de {app}", "Usa este código para que esta sea la dirección de correo de tu cuenta de {app}.", "Confirmar correo"},
	twoFactor: action{"Tu código de verificación de {app}", "Usa este código para activar la verificación en dos pasos de tu cuenta de {app}.", "Verificar"},
	login:     action{"Tu código de inicio de sesión de {app}", "Usa este código para iniciar sesión en {app}.", "Iniciar sesión"},
	reset:     action{"Restablece tu contraseña de {app}", "Usa este enlace para restablecer tu contraseña de {app}.", "Restablecer contraseña"},
	invite:    action{"Te han invitado a {app}", "Te han invitado a unirte a {app}. Sigue el enlace para crear tu cuenta.", "Crear cuenta"},
	exists:    action{"Alguien intentó usar tu correo de {app}", "Alguien acaba de intentar usar este correo electrónico para otra cuenta de {app}. Ya pertenece a tu cuenta, así que no se cambió nada. Si fuiste tú, inicia sesión con este correo o elige una nueva contraseña con este enlace.", "Restablecer contraseña"},

	deviceSubject:   "Nuevo dispositivo en tu cuenta de {app}",
	deviceIntro:     "Alguien está iniciando sesión en tu cuenta de {app} desde un dispositivo nuevo. Si eres tú, introduce este código:",
	deviceWarning:   "Si no eres tú, no compartas el código y cambia tu contraseña: quien lo intenta la conoce.",
	ignore:          "Si no lo has solicitado, puedes ignorar este correo.",
	footer:          "Este es un mensaje automático de {app}.",
	welcomeSubject:  "Bienvenido a {app}",
	welcomeBody:     "Tu cuenta de {app} está lista.",
	changedSubject:  "Se cambió el {field} de tu cuenta de {app}",
	changedBody:     "El {field} de tu cuenta de {app} se cambió a {value}. Si no fuiste tú, protege tu cuenta ahora.",
	email:           "correo electrónico",
	phone:           "teléfono",
	enrolledSubject: "Un nuevo dispositivo puede iniciar sesión en tu cuenta de {app}",
	enrolledBody:    "{device} se registró en tu cuenta de {app} el {date} y ya puede iniciar sesión como tú. Si no fuiste tú, revócalo y protege tu correo ahora.",
	newDevice:       "Un dispositivo nuevo",
	mfaResetSubject: "Se restableció la verificación en dos pasos de tu cuenta de {app}",
	mfaResetBody:    "Un administrador eliminó las llaves de acceso, los segundos factores, los códigos de respaldo y las llaves de dispositivo de tu cuenta de {app} y cerró todas sus sesiones. Vuelve a configurar la verificación en dos pasos la próxima vez que inicies sesión. Si no lo pediste, contacta con soporte ahora.",
	existsNote:      "Si no fuiste tú, puedes ignorar este correo. Tu cuenta no ha cambiado.",
}

// email is one message before layout: a line saying what it is for, an
// optional code and link, and a closing note.
type email struct{ subject, intro, code, button, link, note string }

// emailTemplate is the built-in content for msg.Kind.
func emailTemplate(app string, msg iam.EmailMessage) (Content, error) {
	c, lang := english, "en"
	if msg.Language == "es" {
		c, lang = spanish, "es"
	}
	code, link := strings.TrimSpace(msg.Code), strings.TrimSpace(msg.Link)
	vars := []string{"{app}", app}
	var e email
	switch msg.Kind {
	case iam.MessageVerification:
		a := c.verify
		switch msg.Purpose {
		case iam.PurposeContactChange:
			a = c.change
		case iam.PurposeTwoFactorSetup:
			a = c.twoFactor
		case iam.PurposePasswordlessLogin, iam.PurposeDeviceKeyEnrollment:
			a = c.login
		}
		e = email{a.subject, a.intro, code, a.button, link, c.ignore}
	case iam.MessageLoginCode:
		e = email{subject: c.login.subject, intro: c.login.intro, code: code, note: c.ignore}
	case iam.MessageNewDeviceCode:
		e = email{subject: c.deviceSubject, intro: c.deviceIntro, code: code, note: c.deviceWarning}
	case iam.MessagePasswordReset:
		e = email{c.reset.subject, c.reset.intro, "", c.reset.button, link, c.ignore}
	case iam.MessageInvite:
		e = email{subject: c.invite.subject, intro: c.invite.intro, button: c.invite.button, link: link}
	case iam.MessageAccountExists:
		e = email{c.exists.subject, c.exists.intro, "", c.exists.button, link, c.existsNote}
	case iam.MessageWelcome:
		e = email{subject: c.welcomeSubject, intro: c.welcomeBody}
	case iam.MessageContactChanged:
		ch := msg.ContactChange
		if ch == nil {
			return Content{}, errors.New("contact_changed email needs a ContactChange")
		}
		field := c.email
		if ch.Field == iam.ContactPhone {
			field = c.phone
		}
		vars = append(vars, "{field}", field, "{value}", ch.NewValue)
		e = email{subject: c.changedSubject, intro: c.changedBody}
	case iam.MessageDeviceKeyEnrolled:
		key := msg.DeviceKey
		if key == nil {
			return Content{}, errors.New("device_key_enrolled email needs a DeviceKey")
		}
		device := strings.TrimSpace(key.Label)
		if device == "" {
			device = c.newDevice
		}
		vars = append(vars, "{device}", device, "{date}", key.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"))
		e = email{subject: c.enrolledSubject, intro: c.enrolledBody}
	case iam.MessageMFAReset:
		e = email{subject: c.mfaResetSubject, intro: c.mfaResetBody}
	default:
		return Content{}, fmt.Errorf("smtp: no built-in template for message kind %q", msg.Kind)
	}
	fill := strings.NewReplacer(vars...).Replace
	e.subject, e.intro, e.note = fill(e.subject), fill(e.intro), fill(e.note)
	return e.render(lang, app, fill(c.footer)), nil
}

const (
	fontStack   = `-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif`
	monoStack   = `ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace`
	buttonColor = "#2563eb" // white text 5.2:1
	linkColor   = "#3570ee" // 4.5:1 on white, 4.2:1 on #121212
)

// layout is every built-in email's HTML: tables and inline styles only, and
// no set text or page colors, so a client's light or dark scheme applies;
// borders and the code's box are translucent grey over either.
const layout = `<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="x-apple-disable-message-reformatting">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>{title}</title>
</head>
<body style="margin:0;padding:0;-webkit-text-size-adjust:100%">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
<tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:480px">
<tr><td align="center" style="padding:0 0 20px;font-family:{font};font-size:20px;line-height:28px;font-weight:700">{app}</td></tr>
<tr><td style="padding:32px 24px 8px;border:1px solid #d9d9d9;border-color:rgba(128,128,128,.35);border-radius:12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{body}</table>
</td></tr>
<tr><td align="center" style="padding:20px 0 0;font-family:{font};font-size:12px;line-height:18px;opacity:.7">{footer}</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
`

func (e email) render(lang, app, footer string) Content {
	text := []string{e.intro}
	rows := row("padding:0 0 24px", escapeHTML(e.intro))
	if e.code != "" {
		text = append(text, e.code)
		rows += row("padding:0 0 24px", `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>`+
			`<td align="center" style="padding:16px 8px 16px 16px;border-radius:8px;background-color:#efefef;background-color:rgba(128,128,128,.14);`+
			`font-family:`+monoStack+`;font-size:32px;line-height:40px;font-weight:700;letter-spacing:8px;word-break:break-all;-webkit-user-select:all;user-select:all">`+
			escapeHTML(e.code)+`</td></tr></table>`)
	}
	if e.link != "" {
		text = append(text, e.button+": "+e.link)
		href := escapeHTML(e.link)
		rows += row("padding:0 0 12px", `<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>`+
			`<td style="border-radius:8px;background-color:`+buttonColor+`"><a href="`+href+`" style="display:inline-block;padding:12px 24px;border-radius:8px;`+
			`font-family:`+fontStack+`;font-size:16px;line-height:20px;font-weight:600;color:#ffffff;text-decoration:none">`+escapeHTML(e.button)+`</a></td></tr></table>`)
		rows += row("padding:0 0 24px;font-size:13px;line-height:20px;word-break:break-all", `<a href="`+href+`" style="color:`+linkColor+`">`+href+`</a>`)
	}
	if e.note != "" {
		text = append(text, e.note)
		rows += row("padding:0 0 24px;font-size:14px;line-height:20px;opacity:.7", escapeHTML(e.note))
	}
	html := strings.NewReplacer("{lang}", lang, "{title}", escapeHTML(e.subject), "{font}", fontStack, "{app}", escapeHTML(app),
		"{body}", rows, "{footer}", escapeHTML(footer)).Replace(layout)
	return Content{Subject: e.subject, Text: strings.Join(text, "\n\n"), HTML: html}
}

func row(style, inner string) string {
	return `<tr><td style="font-family:` + fontStack + `;font-size:16px;line-height:24px;` + style + `">` + inner + `</td></tr>`
}

var htmlEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	"\"", "&quot;",
	"'", "&#39;",
)

func escapeHTML(v string) string { return htmlEscaper.Replace(v) }
