package smtp

import (
	"encoding/json"
	"github.com/open-rails/authkit/iam"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEmailPreviewCatalog(t *testing.T) {
	out := os.Getenv("EMAIL_PREVIEW_OUT")
	if out == "" {
		t.Skip("set EMAIL_PREVIEW_OUT to render visual fixtures")
	}
	var records []map[string]string
	emit := func(id, subject, body, text string) {
		if err := os.WriteFile(filepath.Join(out, "html", id+".html"), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "text", id+".txt"), []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
		records = append(records, map[string]string{"id": id, "subject": subject})
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageVerification, Language: "en", Username: "reader", Code: "482916", Purpose: iam.PurposeSignup, Link: "https://example.com/verify-registration?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-verify-signup-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageVerification, Language: "en", Username: "reader", Code: "482916", Purpose: iam.PurposeContactVerify, Link: "https://example.com/verify-registration?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-verify-contact-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageVerification, Language: "en", Username: "reader", Code: "482916", Purpose: iam.PurposeContactChange, Link: "https://example.com/verify-registration?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-verify-change-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageVerification, Language: "en", Username: "reader", Code: "482916", Purpose: iam.PurposePasswordlessLogin, Link: "https://example.com/verify-registration?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-verify-passwordless-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageVerification, Language: "en", Username: "reader", Code: "482916", Purpose: iam.PurposeTwoFactorSetup}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-verify-two-factor-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageVerification, Language: "en", Username: "reader", Code: "482916", Purpose: iam.PurposeDeviceKeyEnrollment}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-verify-device-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageLoginCode, Language: "en", Username: "reader", Code: "482916"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-login-code-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessagePasswordReset, Language: "en", Username: "reader", Code: "482916", Link: "https://example.com/reset-password?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-password-reset-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageNewDeviceCode, Language: "en", Username: "reader", Code: "482916"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-new-device-code-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageWelcome, Language: "en", Username: "reader", Code: "482916"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-welcome-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageInvite, Language: "en", Username: "reader", Code: "482916", Link: "https://example.com/verify-registration?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-invite-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageContactChanged, Language: "en", Username: "reader", Code: "482916", ContactChange: &iam.ContactChange{Field: iam.ContactEmail, NewValue: "new-reader@example.com"}}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-contact-email-changed-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageContactChanged, Language: "en", Username: "reader", Code: "482916", ContactChange: &iam.ContactChange{Field: iam.ContactPhone, NewValue: "+1 202 555 0142"}}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-contact-phone-changed-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageDeviceKeyEnrolled, Language: "en", Username: "reader", Code: "482916", DeviceKey: &iam.DeviceKeyNotice{Label: "Reader laptop", CreatedAt: time.Date(2026, 11, 7, 9, 30, 0, 0, time.UTC)}}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-device-enrolled-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageMFAReset, Language: "en", Username: "reader", Code: "482916"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-mfa-reset-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageAccountExists, Language: "en", Username: "reader", Code: "482916", Link: "https://example.com/reset-password?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-account-exists-en", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageVerification, Language: "es", Username: "reader", Code: "482916", Purpose: iam.PurposeSignup, Link: "https://example.com/verify-registration?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-verify-signup-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageVerification, Language: "es", Username: "reader", Code: "482916", Purpose: iam.PurposeContactVerify, Link: "https://example.com/verify-registration?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-verify-contact-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageVerification, Language: "es", Username: "reader", Code: "482916", Purpose: iam.PurposeContactChange, Link: "https://example.com/verify-registration?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-verify-change-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageVerification, Language: "es", Username: "reader", Code: "482916", Purpose: iam.PurposePasswordlessLogin, Link: "https://example.com/verify-registration?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-verify-passwordless-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageVerification, Language: "es", Username: "reader", Code: "482916", Purpose: iam.PurposeTwoFactorSetup}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-verify-two-factor-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageVerification, Language: "es", Username: "reader", Code: "482916", Purpose: iam.PurposeDeviceKeyEnrollment}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-verify-device-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageLoginCode, Language: "es", Username: "reader", Code: "482916"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-login-code-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessagePasswordReset, Language: "es", Username: "reader", Code: "482916", Link: "https://example.com/reset-password?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-password-reset-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageNewDeviceCode, Language: "es", Username: "reader", Code: "482916"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-new-device-code-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageWelcome, Language: "es", Username: "reader", Code: "482916"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-welcome-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageInvite, Language: "es", Username: "reader", Code: "482916", Link: "https://example.com/verify-registration?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-invite-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageContactChanged, Language: "es", Username: "reader", Code: "482916", ContactChange: &iam.ContactChange{Field: iam.ContactEmail, NewValue: "new-reader@example.com"}}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-contact-email-changed-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageContactChanged, Language: "es", Username: "reader", Code: "482916", ContactChange: &iam.ContactChange{Field: iam.ContactPhone, NewValue: "+1 202 555 0142"}}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-contact-phone-changed-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageDeviceKeyEnrolled, Language: "es", Username: "reader", Code: "482916", DeviceKey: &iam.DeviceKeyNotice{Label: "Reader laptop", CreatedAt: time.Date(2026, 11, 7, 9, 30, 0, 0, time.UTC)}}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-device-enrolled-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageMFAReset, Language: "es", Username: "reader", Code: "482916"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-mfa-reset-es", c.Subject, c.HTML, c.Text)
	}
	{
		msg := iam.EmailMessage{Kind: iam.MessageAccountExists, Language: "es", Username: "reader", Code: "482916", Link: "https://example.com/reset-password?token=sample"}
		c, e := emailTemplate("Example", msg)
		if e != nil {
			t.Fatal(e)
		}
		emit("authkit-account-exists-es", c.Subject, c.HTML, c.Text)
	}
	b, e := json.Marshal(records)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(out, "authkit-subjects.json"), b, 0644); e != nil {
		t.Fatal(e)
	}
}
