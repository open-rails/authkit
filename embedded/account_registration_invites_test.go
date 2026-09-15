package embedded

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
)

// inviteCaptureEmailSender records account-registration-invite sends (#223 — the
// original bug was a type assertion that could never succeed, so the invite email
// was silently never sent; these fields let tests assert delivery actually happens).
type inviteCaptureEmailSender struct {
	inviteEmail string
	inviteURL   string
	inviteErr   error // returned from SendAccountRegistrationInvite to exercise the failure path
}

func (s *inviteCaptureEmailSender) SendVerification(context.Context, string, string, VerificationMessage) error {
	return nil
}
func (s *inviteCaptureEmailSender) SendPasswordResetLink(context.Context, string, string, string) error {
	return nil
}
func (s *inviteCaptureEmailSender) SendAccountRegistrationInvite(_ context.Context, email, inviteURL string) error {
	s.inviteEmail, s.inviteURL = email, inviteURL
	return s.inviteErr
}
func (s *inviteCaptureEmailSender) SendLoginCode(context.Context, string, string, string) error {
	return nil
}
func (s *inviteCaptureEmailSender) SendWelcome(context.Context, string, string) error { return nil }
func (s *inviteCaptureEmailSender) SendDeviceKeyEnrolled(context.Context, string, string, DeviceKeyNotice) error {
	return nil
}
func (s *inviteCaptureEmailSender) SendContactChanged(context.Context, string, string, ContactChange) error {
	return nil
}

// #223: the configured host EmailSender must RECEIVE the invite send — and a
// failing provider must not panic or propagate (the inviter still holds the URL).
// No DB needed: this exercises the send helper directly.
func TestSendAccountRegistrationInviteEmail_DeliversToHostSender(t *testing.T) {
	sender := &inviteCaptureEmailSender{}
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithEmailSender(sender))

	svc.sendAccountRegistrationInviteEmail(context.Background(), "invitee@example.com", "https://test/invite?account_invite_token=abc")
	if sender.inviteEmail != "invitee@example.com" || sender.inviteURL != "https://test/invite?account_invite_token=abc" {
		t.Fatalf("host sender did not receive the invite send: email=%q url=%q", sender.inviteEmail, sender.inviteURL)
	}

	// Failure path: swallowed (logged), never panics/propagates.
	sender.inviteErr = errors.New("smtp down")
	svc.sendAccountRegistrationInviteEmail(context.Background(), "second@example.com", "https://test/invite?account_invite_token=def")
	if sender.inviteEmail != "second@example.com" {
		t.Fatalf("failure-path send was not attempted")
	}
}

// #147 register+join: a role-carrying account-registration invite lets a STRANGER
// register and receive the group role in ONE consume — no separate group invite.
func TestAccountRegistrationInvite_RegisterPlusJoin(t *testing.T) {
	svc, pool, ctx := setupInviteLinkTest(t, RegistrationModeInviteOnly)
	owner := acmeOwner(t, svc, ctx, pool)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1e10)
	email := "joiner-" + suffix + "@example.com"
	username := "joiner" + suffix

	// The org owner mints a role-carrying invite (authorized by org members:manage,
	// NOT root:users:invite).
	created, err := svc.CreateAccountRegistrationInvite(ctx, CreateAccountRegistrationInviteRequest{
		Email:        email,
		InvitedBy:    owner,
		Persona:      "org",
		InstanceSlug: "acme",
		Role:         "member",
	})
	if err != nil {
		t.Fatalf("CreateAccountRegistrationInvite (register+join): %v", err)
	}
	if created.Persona != "org" || created.Role != "member" {
		t.Fatalf("created invite did not echo the carried role: %+v", created)
	}

	if _, err := svc.registerAccount(ctx, accountRegistration{User: ImportUserInput{Email: email, Username: username, EmailVerified: true}, InviteToken: created.Code}); err != nil {
		t.Fatalf("register+join registration: %v", err)
	}
	u, err := svc.GetUserByEmail(ctx, email)
	if err != nil || u == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	// The single consume both registered the user AND granted the org/acme role.
	if ok, _ := svc.Can(ctx, authkit.UserSubject(u.ID), authkit.GroupRef{Persona: "org", Instance: "acme"}, "org:repo:read"); !ok {
		t.Fatal("register+join did not grant the carried role on consume")
	}
}
