package embedded

import (
	"context"
	"fmt"
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
)

// spyEmailSender records every SendVerification call so a test can assert
// that nothing was sent.
type spyEmailSender struct{ calls int }

func (s *spyEmailSender) SendVerification(ctx context.Context, email, username string, msg VerificationMessage) error {
	s.calls++
	return nil
}

func (s *spyEmailSender) SendPasswordResetLink(ctx context.Context, email, username, token string) error {
	return nil
}

func (s *spyEmailSender) SendAccountRegistrationInvite(ctx context.Context, email, inviteURL string) error {
	return nil
}

func (s *spyEmailSender) SendLoginCode(ctx context.Context, email, username, code string) error {
	return nil
}

func (s *spyEmailSender) SendWelcome(ctx context.Context, email, username string) error {
	return nil
}

func (s *spyEmailSender) SendDeviceKeyEnrolled(context.Context, string, string, DeviceKeyNotice) error {
	return nil
}
func (s *spyEmailSender) SendContactChanged(context.Context, string, string, ContactChange) error {
	return nil
}

// Optional verification has one registration path with and without delivery.
func TestOptionalRegistrationWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	for _, sender := range []bool{false, true} {
		t.Run(fmt.Sprint("sender=", sender), func(t *testing.T) {
			spy := &spyEmailSender{}
			deps := Deps{Postgres: pg.Pool}
			if sender {
				deps.Email = spy
			}
			svc, err := New(Config{Keys: staticTestKeys(t), Token: TokenConfig{Issuer: "https://test", IssuedAudiences: []string{"app"}}, Registration: RegistrationConfig{Verification: RegistrationVerificationOptional}, Ephemeral: EphemeralConfig{AllowMemory: true}}, deps)
			if err != nil {
				t.Fatal(err)
			}
			email, username := fmt.Sprintf("optional-%t@example.com", sender), fmt.Sprintf("optional%t", sender)
			out, err := svc.Register(t.Context(), RegisterInput{Identifier: email, Username: username, Password: "Correct-horse-battery-1"})
			if err != nil {
				t.Fatal(err)
			}
			if out.Kind != RegisterSessionIssued || out.Session.AccessToken == "" {
				t.Fatalf("registration did not issue session: %+v", out)
			}
			user, err := svc.GetUserByEmail(t.Context(), email)
			if err != nil {
				t.Fatal(err)
			}
			if user.EmailVerified == sender || (spy.calls == 1) != sender {
				t.Fatalf("verified=%t sends=%d", user.EmailVerified, spy.calls)
			}
		})
	}
}
