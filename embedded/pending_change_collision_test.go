package embedded

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/password"
	"github.com/stretchr/testify/require"
)

type codeCaptureEmailSender struct {
	mu    sync.Mutex
	codes map[string]string
}

func (c *codeCaptureEmailSender) SendVerification(_ context.Context, email, _ string, msg VerificationMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.codes == nil {
		c.codes = map[string]string{}
	}
	c.codes[email] = msg.Code
	return nil
}
func (c *codeCaptureEmailSender) SendPasswordResetLink(context.Context, string, string, string) error {
	return nil
}
func (c *codeCaptureEmailSender) SendAccountRegistrationInvite(context.Context, string, string) error {
	return nil
}
func (c *codeCaptureEmailSender) SendLoginCode(context.Context, string, string, string) error {
	return nil
}
func (c *codeCaptureEmailSender) SendWelcome(context.Context, string, string) error { return nil }
func (c *codeCaptureEmailSender) SendDeviceKeyEnrolled(context.Context, string, string, DeviceKeyNotice) error {
	return nil
}
func (c *codeCaptureEmailSender) SendContactChanged(context.Context, string, string, ContactChange) error {
	return nil
}

func (c *codeCaptureEmailSender) code(email string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.codes[email]
}

// #301: two strangers whose pending registrations draw the same 6-digit code must
// never share storage. Records are keyed by (kind, target) with the code hash
// inside, so A's resend cannot rewrite A from B's payload or delete B's record,
// and each account is created from its own username/password. The collision is
// forced by re-issuing B's record under A's code (the RNG outcome, nothing else).
func TestPendingRegistration_SameCodeTwoUsers(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	sender := &codeCaptureEmailSender{}
	svc := mustNewWithKeys(t,
		Config{Token: TokenConfig{Issuer: "https://test"}, Registration: RegistrationConfig{Verification: RegistrationVerificationRequired}},
		Keyset{},
		WithPostgres(pool), WithEphemeralStore(memorystore.NewKV()), WithEmailSender(sender),
	)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	emailA, userA, passA := "col-a-"+suffix+"@example.com", "cola"+suffix, "password-A-"+suffix
	emailB, userB, passB := "col-b-"+suffix+"@example.com", "colb"+suffix, "password-B-"+suffix
	hashA, err := password.HashArgon2id(passA)
	require.NoError(t, err)
	hashB, err := password.HashArgon2id(passB)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email = ANY($1::text[])`, []string{emailA, emailB})
	})

	codeA, err := svc.CreatePendingRegistrationWithLanguage(ctx, emailA, userA, hashA, 0, "")
	require.NoError(t, err)
	_, err = svc.CreatePendingRegistrationWithLanguage(ctx, emailB, userB, hashB, 0, "")
	require.NoError(t, err)

	forceSameCode := func(code string) {
		recB, ok := svc.findPendingChangeByTarget(ctx, KindRegisterEmail, emailB)
		require.True(t, ok)
		recB.CodeHash = sha256Hex(code)
		require.NoError(t, svc.storePendingChange(ctx, recB, 0))
	}
	forceSameCode(codeA)

	// A's resend re-issues A from A's own payload and leaves B untouched.
	require.NoError(t, svc.RequestEmailVerification(ctx, emailA, 0))
	codeA2 := sender.code(emailA)
	require.Len(t, codeA2, 6)
	recA, ok := svc.findPendingChangeByTarget(ctx, KindRegisterEmail, emailA)
	require.True(t, ok)
	require.Equal(t, userA, recA.Username)
	require.Equal(t, hashA, recA.PasswordHash)
	require.Equal(t, sha256Hex(codeA2), recA.CodeHash)
	recB, ok := svc.findPendingChangeByTarget(ctx, KindRegisterEmail, emailB)
	require.True(t, ok)
	require.Equal(t, userB, recB.Username)
	require.Equal(t, hashB, recB.PasswordHash)
	require.Equal(t, sha256Hex(codeA), recB.CodeHash)

	// Both outstanding with the same code again: each verifies only its own hash.
	forceSameCode(codeA2)
	require.True(t, svc.VerifyPendingPassword(ctx, emailA, passA))
	require.False(t, svc.VerifyPendingPassword(ctx, emailA, passB))
	require.True(t, svc.VerifyPendingPassword(ctx, emailB, passB))

	// Both confirm with the shared code, each landing on its own account.
	uidA, err := svc.ConfirmPendingRegistration(ctx, emailA, codeA2)
	require.NoError(t, err)
	uidB, err := svc.ConfirmPendingRegistration(ctx, emailB, codeA2)
	require.NoError(t, err)
	require.NotEqual(t, uidA, uidB)

	ua, err := svc.getUserByID(ctx, uidA)
	require.NoError(t, err)
	require.Equal(t, userA, *ua.Username)
	require.True(t, svc.CheckUserPassword(ctx, uidA, passA) == nil)
	require.False(t, svc.CheckUserPassword(ctx, uidA, passB) == nil)
	ub, err := svc.getUserByID(ctx, uidB)
	require.NoError(t, err)
	require.Equal(t, userB, *ub.Username)
	require.True(t, svc.CheckUserPassword(ctx, uidB, passB) == nil)

	// Confirmation consumed only the confirmed record; nothing is left behind.
	_, ok = svc.findPendingChangeByTarget(ctx, KindRegisterEmail, emailA)
	require.False(t, ok)
	_, ok = svc.findPendingChangeByTarget(ctx, KindRegisterEmail, emailB)
	require.False(t, ok)
}
