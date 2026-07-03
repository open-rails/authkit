package authcore

import (
	"context"
	"testing"

	memorystore "github.com/open-rails/authkit/storage/memory"
)

// AK security audit F1: the typed 6-digit email-verification / pending-registration
// code is looked up globally by hash. It MUST be scoped to a specific email so a
// guessed code can't confirm (and take over) whichever account happens to hold it,
// and a per-email attempt counter must invalidate the code after a few wrong
// guesses so it can't be brute-forced within its TTL.

func newEmailVerifyTestService() *Service {
	return NewService(
		Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired}},
		Keyset{},
		WithEphemeralStore(memorystore.NewKV()),
	)
}

func TestConfirmPendingRegistration_IsEmailScoped(t *testing.T) {
	svc := newEmailVerifyTestService()
	ctx := context.Background()

	code, err := svc.CreatePendingRegistrationWithLanguage(ctx, "victim@example.com", "victim", "argon2id$hash", 0, "")
	if err != nil {
		t.Fatalf("CreatePendingRegistration: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}

	// A correct code paired with the WRONG email must be rejected...
	if _, err := svc.ConfirmPendingRegistration(ctx, "attacker@example.com", code); err == nil {
		t.Fatal("a code confirmed against a different email must be rejected (global-collision takeover)")
	}
	// ...and must NOT consume the legitimate owner's still-valid code.
	if _, ok, _ := svc.loadPendingChangeByToken(ctx, sha256Hex(code)); !ok {
		t.Fatal("a mismatched-email guess must not consume the legitimate code")
	}

	// A wrong code for the right email is rejected too.
	if _, err := svc.ConfirmPendingRegistration(ctx, "victim@example.com", "000000"); err == nil {
		t.Fatal("a wrong code must be rejected")
	}

	// An empty email is rejected outright.
	if _, err := svc.ConfirmPendingRegistration(ctx, "", code); err == nil {
		t.Fatal("an empty email must be rejected")
	}
}

func TestRecordFailedEmailVerifyCode_InvalidatesAfterCap(t *testing.T) {
	svc := newEmailVerifyTestService()
	ctx := context.Background()

	code, err := svc.CreatePendingRegistrationWithLanguage(ctx, "user@example.com", "user", "argon2id$hash", 0, "")
	if err != nil {
		t.Fatalf("CreatePendingRegistration: %v", err)
	}
	if _, ok, _ := svc.loadPendingChangeByToken(ctx, sha256Hex(code)); !ok {
		t.Fatal("pending code should exist after creation")
	}

	// Below the cap, the outstanding code survives.
	for i := 0; i < maxEmailVerifyCodeAttempts-1; i++ {
		svc.RecordFailedEmailVerifyCode(ctx, "user@example.com")
	}
	if _, ok, _ := svc.loadPendingChangeByToken(ctx, sha256Hex(code)); !ok {
		t.Fatal("code must survive below the attempt cap")
	}

	// Reaching the cap invalidates the outstanding code so guessing can't continue.
	svc.RecordFailedEmailVerifyCode(ctx, "user@example.com")
	if _, ok, _ := svc.loadPendingChangeByToken(ctx, sha256Hex(code)); ok {
		t.Fatal("code must be invalidated once the attempt cap is reached")
	}
}

func TestClearEmailVerifyCodeAttempts_ResetsCounter(t *testing.T) {
	svc := newEmailVerifyTestService()
	ctx := context.Background()

	code, err := svc.CreatePendingRegistrationWithLanguage(ctx, "user@example.com", "user", "argon2id$hash", 0, "")
	if err != nil {
		t.Fatalf("CreatePendingRegistration: %v", err)
	}

	// Rack up cap-1 failures, then a success clears the counter...
	for i := 0; i < maxEmailVerifyCodeAttempts-1; i++ {
		svc.RecordFailedEmailVerifyCode(ctx, "user@example.com")
	}
	svc.ClearEmailVerifyCodeAttempts(ctx, "user@example.com")

	// ...so a fresh run of cap-1 more failures still doesn't invalidate the code.
	for i := 0; i < maxEmailVerifyCodeAttempts-1; i++ {
		svc.RecordFailedEmailVerifyCode(ctx, "user@example.com")
	}
	if _, ok, _ := svc.loadPendingChangeByToken(ctx, sha256Hex(code)); !ok {
		t.Fatal("counter reset should prevent invalidation below a fresh cap")
	}
}
