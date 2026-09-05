package authcore

// ak#322 — session/credential engine hardening, pinned on the real engine and a
// real Postgres. Skips without AUTHKIT_TEST_DATABASE_URL.

import (
	"context"
	"fmt"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	"github.com/stretchr/testify/require"
)

// hardeningEmailSender captures the verification code it is handed and every
// contact-changed / reset-link delivery.
type hardeningEmailSender struct {
	code           string
	resetLinks     int
	contactChanged []struct {
		to     string
		change ContactChange
	}
}

func (s *hardeningEmailSender) SendVerification(_ context.Context, _, _ string, msg VerificationMessage) error {
	s.code = msg.Code
	return nil
}
func (s *hardeningEmailSender) SendPasswordResetLink(context.Context, string, string, string) error {
	s.resetLinks++
	return nil
}
func (s *hardeningEmailSender) SendAccountRegistrationInvite(context.Context, string, string) error {
	return nil
}
func (s *hardeningEmailSender) SendLoginCode(context.Context, string, string, string) error {
	return nil
}
func (s *hardeningEmailSender) SendWelcome(context.Context, string, string) error { return nil }
func (s *hardeningEmailSender) SendDeviceKeyEnrolled(context.Context, string, string, DeviceKeyNotice) error {
	return nil
}
func (s *hardeningEmailSender) SendContactChanged(_ context.Context, to, _ string, change ContactChange) error {
	s.contactChanged = append(s.contactChanged, struct {
		to     string
		change ContactChange
	}{to, change})
	return nil
}

func newHardeningService(t *testing.T) (*Service, *hardeningEmailSender) {
	t.Helper()
	sender := &hardeningEmailSender{}
	svc := mustNewService(t, Config{Token: TokenConfig{Issuer: "https://hardening.test"}}, Keyset{},
		WithPostgres(testPG(t)), WithEphemeralStore(memorystore.NewKV())).WithEmailSender(sender)
	return svc, sender
}

func newHardeningUser(t *testing.T, ctx context.Context, svc *Service, tag string) (*User, string) {
	t.Helper()
	username := fmt.Sprintf("hard-%s-%d", tag, time.Now().UnixNano())
	email := username + "@example.test"
	u, err := svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = svc.pg.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })
	return u, email
}

// A confirmed email change is a recovery-identifier change: every session but
// the confirming one dies with it, and the address that was replaced is told.
func TestConfirmEmailChange_RevokesOtherSessionsAndNotifiesOldAddress(t *testing.T) {
	svc, sender := newHardeningService(t)
	ctx := context.Background()
	u, oldEmail := newHardeningUser(t, ctx, svc, "emailchange")

	keep, _, _, err := svc.IssueRefreshSession(ctx, u.ID, "browser", nil)
	require.NoError(t, err)
	other, _, _, err := svc.IssueRefreshSession(ctx, u.ID, "phone", nil)
	require.NoError(t, err)

	newEmail := "new-" + oldEmail
	require.NoError(t, svc.RequestEmailChange(ctx, u.ID, newEmail))
	require.NotEmpty(t, sender.code)
	require.Empty(t, sender.contactChanged, "the notice goes out on the change, not the request")

	require.NoError(t, svc.ConfirmEmailChange(ctx, u.ID, newEmail, sender.code, &keep))

	after, err := svc.getUserByID(ctx, u.ID)
	require.NoError(t, err)
	require.Equal(t, newEmail, *after.Email)

	live, err := svc.ListUserSessions(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, live, 1)
	require.Equal(t, keep, live[0].ID, "only the confirming session survives")

	events, err := svc.ListSessionEvents(ctx, u.ID, SessionEventRevoked)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, other, events[0].SessionID)
	require.Equal(t, string(SessionRevokeReasonContactChange), *events[0].Reason)

	require.Len(t, sender.contactChanged, 1)
	require.Equal(t, oldEmail, sender.contactChanged[0].to)
	require.Equal(t, ContactChange{Field: "email", NewValue: newEmail}, sender.contactChanged[0].change)
}

// A gated account (here: banned) gets the enumeration-safe 202 on a reset
// request but no token and no message, and a reset token it somehow holds
// cannot write a password hash.
func TestPasswordReset_GatedAccountWritesNothing(t *testing.T) {
	svc, sender := newHardeningService(t)
	ctx := context.Background()
	u, email := newHardeningUser(t, ctx, svc, "bannedreset")
	// Ban state written directly: who may ban is #286's concern, not this gate's.
	_, err := svc.pg.Exec(ctx, `UPDATE profiles.users SET banned_at = now() WHERE id = $1::uuid`, u.ID)
	require.NoError(t, err)

	require.NoError(t, svc.RequestPasswordReset(ctx, email, time.Minute, nil, nil))
	require.Zero(t, sender.resetLinks, "a banned account must not receive a reset link")

	const token = "planted-reset-token"
	require.NoError(t, svc.storePasswordReset(ctx, sha256Hex(token), u.ID, time.Minute))
	_, err = svc.ConfirmPasswordReset(ctx, token, "New-password-12345")
	require.ErrorIs(t, err, ErrUserBanned)
	require.False(t, svc.VerifyUserPassword(ctx, u.ID, "New-password-12345"), "no hash may be written for a gated account")
}

// The reserved-account lookup is part of the liveness gate every login and
// refresh runs through; a lookup that fails must deny, never fall through as
// "not reserved".
func TestEnsureUserAccess_ReservedLookupErrorDenies(t *testing.T) {
	svc, _ := newHardeningService(t)
	ctx := context.Background()
	u, _ := newHardeningUser(t, ctx, svc, "gate")
	require.NoError(t, svc.ensureUserAccess(ctx, u))

	dead, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, svc.ensureUserAccess(dead, u))
}
