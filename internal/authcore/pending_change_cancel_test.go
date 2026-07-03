package authcore

import (
	"context"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
)

// #356: a pending (unverified) email registration must make that email report as
// taken by the availability check — not only committed/verified users.
func TestPendingRegistrationMakesEmailUnavailable(t *testing.T) {
	svc := NewService(Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired}}, Keyset{}, WithEphemeralStore(memorystore.NewKV()))
	ctx := context.Background()

	email := "pending-avail@example.com"
	if _, err := svc.CreatePendingRegistrationWithLanguage(ctx, email, "pendinguser", "argon2id$hash", 0, ""); err != nil {
		t.Fatalf("CreatePendingRegistration failed: %v", err)
	}

	emailTaken, _, err := svc.CheckPendingRegistrationConflict(ctx, email, "")
	if err != nil {
		t.Fatalf("CheckPendingRegistrationConflict error: %v", err)
	}
	if !emailTaken {
		t.Fatalf("expected pending email to be reported as taken")
	}

	// An unrelated email is still available.
	if otherTaken, _, _ := svc.CheckPendingRegistrationConflict(ctx, "free@example.com", ""); otherTaken {
		t.Fatalf("unrelated email should be available")
	}
}

// #356: a pending (unverified) phone registration must make that phone report as
// taken by the availability check.
func TestPendingPhoneRegistrationMakesPhoneUnavailable(t *testing.T) {
	svc := NewService(Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired}}, Keyset{}, WithEphemeralStore(memorystore.NewKV()))
	ctx := context.Background()

	phone := "+14155550987"
	if _, err := svc.CreatePendingPhoneRegistrationWithLanguage(ctx, phone, "pendingphoneuser", "argon2id$hash", ""); err != nil {
		t.Fatalf("CreatePendingPhoneRegistration failed: %v", err)
	}

	phoneTaken, _, err := svc.CheckPhoneRegistrationConflict(ctx, phone, "")
	if err != nil {
		t.Fatalf("CheckPhoneRegistrationConflict error: %v", err)
	}
	if !phoneTaken {
		t.Fatalf("expected pending phone to be reported as taken")
	}
}

// #359/#360: cancelling a pending phone change clears the server-side pending
// verification record. Because the new phone is held only in the pending record
// (no optimistic pre-apply), cancellation has nothing to roll back.
func TestCancelPhoneChangeClearsPendingRecord(t *testing.T) {
	svc := NewService(Config{}, Keyset{}, WithEphemeralStore(memorystore.NewKV()))
	ctx := context.Background()

	userID := "user-123"
	phone := "+14155551234"
	if err := svc.storePendingChange(ctx, pendingChange{
		Kind:   KindChangePhone,
		Target: phone,
		UserID: userID,
	}, map[string]time.Duration{
		sha256Hex("ABC123"): defaultPhoneVerificationTTL,
	}); err != nil {
		t.Fatalf("seed storePendingChange failed: %v", err)
	}
	if _, ok := svc.findPendingChangeByUser(ctx, KindChangePhone, userID); !ok {
		t.Fatalf("expected pending phone change before cancel")
	}

	if err := svc.CancelPhoneChange(ctx, userID, phone); err != nil {
		t.Fatalf("CancelPhoneChange failed: %v", err)
	}
	if _, ok := svc.findPendingChangeByUser(ctx, KindChangePhone, userID); ok {
		t.Fatalf("expected pending phone change to be cleared after cancel")
	}

	// Idempotent: cancelling again is a no-op, not an error.
	if err := svc.CancelPhoneChange(ctx, userID, phone); err != nil {
		t.Fatalf("CancelPhoneChange idempotent call failed: %v", err)
	}

	// A cancel by one user must NOT delete another user's pending change.
	otherUser := "user-999"
	if err := svc.storePendingChange(ctx, pendingChange{
		Kind:   KindChangePhone,
		Target: "+14155559999",
		UserID: otherUser,
	}, map[string]time.Duration{
		sha256Hex("ZZZ999"): defaultPhoneVerificationTTL,
	}); err != nil {
		t.Fatalf("seed other pending change failed: %v", err)
	}
	if err := svc.CancelPhoneChange(ctx, userID, phone); err != nil {
		t.Fatalf("CancelPhoneChange cross-user failed: %v", err)
	}
	if _, ok := svc.findPendingChangeByUser(ctx, KindChangePhone, otherUser); !ok {
		t.Fatalf("cancel by one user must not delete another user's pending change")
	}
}

// #359: CancelEmailChange is a safe idempotent no-op when there is no pending
// change.
func TestCancelEmailChangeNoPendingIsNoOp(t *testing.T) {
	svc := NewService(Config{}, Keyset{}, WithEphemeralStore(memorystore.NewKV()))
	if err := svc.CancelEmailChange(context.Background(), "user-123"); err != nil {
		t.Fatalf("CancelEmailChange no-op failed: %v", err)
	}
}
