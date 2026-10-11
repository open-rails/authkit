package twilio

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-rails/authkit/iam"
)

// smsTemplate is the built-in body for msg.Kind; a code message ends with
// its origin-bound line (msg.OriginBoundLine).
func smsTemplate(app string, msg iam.SMSMessage) (string, error) {
	body, err := smsBody(app, msg)
	if err != nil {
		return "", err
	}
	if line := msg.OriginBoundLine(); line != "" {
		body += "\n\n" + line
	}
	return body, nil
}

func smsBody(app string, msg iam.SMSMessage) (string, error) {
	es := msg.Language == "es"
	switch msg.Kind {
	case iam.MessageVerification:
		change := msg.Purpose == iam.PurposeContactChange
		parts := make([]string, 0, 2)
		if code := strings.TrimSpace(msg.Code); code != "" {
			switch {
			case es && change:
				parts = append(parts, fmt.Sprintf("%s codigo de confirmacion: %s", app, code))
			case es:
				parts = append(parts, fmt.Sprintf("%s codigo de verificacion: %s", app, code))
			case change:
				parts = append(parts, fmt.Sprintf("%s change confirmation code: %s", app, code))
			default:
				parts = append(parts, fmt.Sprintf("%s verification code: %s", app, code))
			}
		}
		if link := strings.TrimSpace(msg.Link); link != "" {
			if es {
				parts = append(parts, "Verificar: "+link)
			} else {
				parts = append(parts, "Verify: "+link)
			}
		}
		return strings.Join(parts, "\n"), nil
	case iam.MessageLoginCode:
		if es {
			return fmt.Sprintf("%s codigo de inicio: %s", app, strings.TrimSpace(msg.Code)), nil
		}
		return fmt.Sprintf("%s login code: %s", app, strings.TrimSpace(msg.Code)), nil
	case iam.MessageNewDeviceCode:
		if es {
			return fmt.Sprintf("%s codigo de nuevo dispositivo: %s. Si no eres tu, cambia tu contrasena.", app, strings.TrimSpace(msg.Code)), nil
		}
		return fmt.Sprintf("%s new device code: %s. If this isn't you, change your password.", app, strings.TrimSpace(msg.Code)), nil
	case iam.MessagePasswordReset:
		if es {
			return fmt.Sprintf("%s restablecer contrasena: %s", app, strings.TrimSpace(msg.Link)), nil
		}
		return fmt.Sprintf("%s password reset: %s", app, strings.TrimSpace(msg.Link)), nil
	case iam.MessageContactChanged:
		ch := msg.ContactChange
		if ch == nil {
			return "", errors.New("contact_changed SMS needs a ContactChange")
		}
		return fmt.Sprintf("%s: the %s on your account was changed to %s. If this was not you, secure your account now.", app, ch.Field, ch.NewValue), nil
	}
	return "", fmt.Errorf("twilio SMS: no built-in template for message kind %q", msg.Kind)
}
