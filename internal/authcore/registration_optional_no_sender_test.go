package authcore

import (
	"context"
	"fmt"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/storage/memory"
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

// Locks in the graceful-degrade contract first-party embedders rely on:
// under RegistrationVerificationOptional with NO email sender configured,
// a registration creates the user already-verified and sends nothing.
// Skips without AUTHKIT_TEST_DATABASE_URL (createEmailRegistrationUser needs PG).
func TestRegistrationOptionalNoSenderCreatesVerifiedAndSendsNothing(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()

	// Optional policy, no WithEmailSender => s.email == nil.
	svc := NewService(Options{Issuer: "https://test", RegistrationVerification: RegistrationVerificationOptional}, Keyset{}, WithPostgres(pool))

	email := fmt.Sprintf("opt-no-sender-%d@example.com", time.Now().UnixNano())
	username := fmt.Sprintf("optnosender%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	code, err := svc.CreatePendingRegistration(ctx, email, username, "argon2id$hash", 0)
	if err != nil {
		t.Fatalf("CreatePendingRegistration: %v", err)
	}
	// Graceful degrade: nothing to send, so no verification code is issued.
	if code != "" {
		t.Fatalf("expected empty code (nothing sent) under Optional+no-sender, got %q", code)
	}

	u, err := svc.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if u == nil {
		t.Fatal("expected user to be created under Optional+no-sender")
	}
	if !u.EmailVerified {
		t.Fatal("expected user to be created already-verified under Optional+no-sender")
	}
}

// Companion: with a sender configured under Optional, a code IS issued and the
// sender IS invoked (the user is left unverified pending confirmation). This
// pins the "no-sender" branch above as the genuine degrade path, not an accident.
func TestRegistrationOptionalWithSenderSendsAndLeavesUnverified(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()

	spy := &spyEmailSender{}
	svc := NewService(Options{Issuer: "https://test", RegistrationVerification: RegistrationVerificationOptional}, Keyset{},
		WithPostgres(pool), WithEmailSender(spy), WithEphemeralStore(memorystore.NewKV(), EphemeralMemory))

	email := fmt.Sprintf("opt-sender-%d@example.com", time.Now().UnixNano())
	username := fmt.Sprintf("optsender%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	code, err := svc.CreatePendingRegistration(ctx, email, username, "argon2id$hash", 0)
	if err != nil {
		t.Fatalf("CreatePendingRegistration: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit verification code under Optional+sender, got %q", code)
	}
	if spy.calls != 1 {
		t.Fatalf("expected exactly one SendVerification call, got %d", spy.calls)
	}

	u, err := svc.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if u == nil || u.EmailVerified {
		t.Fatalf("expected unverified user pending confirmation under Optional+sender, got %+v", u)
	}
}
