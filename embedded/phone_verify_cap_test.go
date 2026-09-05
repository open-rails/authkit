package embedded

import (
	"context"
	"testing"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
)

// Phone twin of the email attempt-cap tests (email_verify_scope_test.go): the typed
// 6-digit SMS code must be invalidated after a per-phone wrong-guess cap so it can't
// be brute-forced within its TTL, and a success must reset the counter.

func newPhoneVerifyTestService(t *testing.T) *Client {
	t.Helper()
	return mustNewWithKeys(t,
		Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired, AllowMissingSenders: true}},
		Keyset{},
		WithEphemeralStore(memorystore.NewKV()),
	)
}

func pendingPhoneRegistrationExists(svc *Client, phone string) bool {
	_, ok := svc.findPendingChangeByTarget(context.Background(), KindRegisterPhone, phone)
	return ok
}

func TestRecordFailedPhoneVerifyCode_InvalidatesAfterCap(t *testing.T) {
	svc := newPhoneVerifyTestService(t)
	ctx := context.Background()
	const phone = "+14155550123"

	if _, err := svc.CreatePendingPhoneRegistrationWithLanguage(ctx, phone, "capuser", "argon2id$hash", ""); err != nil {
		t.Fatalf("CreatePendingPhoneRegistration: %v", err)
	}
	if !pendingPhoneRegistrationExists(svc, phone) {
		t.Fatal("pending phone code should exist after creation")
	}

	// Below the cap, the outstanding code survives.
	for i := 0; i < maxPhoneVerifyCodeAttempts-1; i++ {
		svc.RecordFailedPhoneVerifyCode(ctx, phone)
	}
	if !pendingPhoneRegistrationExists(svc, phone) {
		t.Fatal("code must survive below the attempt cap")
	}

	// Reaching the cap invalidates the outstanding code so guessing can't continue.
	svc.RecordFailedPhoneVerifyCode(ctx, phone)
	if pendingPhoneRegistrationExists(svc, phone) {
		t.Fatal("code must be invalidated once the attempt cap is reached")
	}
}

func TestClearPhoneVerifyCodeAttempts_ResetsCounter(t *testing.T) {
	svc := newPhoneVerifyTestService(t)
	ctx := context.Background()
	const phone = "+14155550124"

	if _, err := svc.CreatePendingPhoneRegistrationWithLanguage(ctx, phone, "capuser2", "argon2id$hash", ""); err != nil {
		t.Fatalf("CreatePendingPhoneRegistration: %v", err)
	}

	// cap-1 failures, then a success clears the counter...
	for i := 0; i < maxPhoneVerifyCodeAttempts-1; i++ {
		svc.RecordFailedPhoneVerifyCode(ctx, phone)
	}
	svc.ClearPhoneVerifyCodeAttempts(ctx, phone)

	// ...so a fresh run of cap-1 more failures still doesn't invalidate the code.
	for i := 0; i < maxPhoneVerifyCodeAttempts-1; i++ {
		svc.RecordFailedPhoneVerifyCode(ctx, phone)
	}
	if !pendingPhoneRegistrationExists(svc, phone) {
		t.Fatal("counter reset should prevent invalidation below a fresh cap")
	}
}
