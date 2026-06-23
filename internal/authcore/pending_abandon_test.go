package authcore

import (
	"context"
	"testing"

	memorystore "github.com/open-rails/authkit/storage/memory"
)

func TestDeletePendingRegistrationByEmail(t *testing.T) {
	svc := NewService(Options{RegistrationVerification: RegistrationVerificationRequired}, Keyset{}, WithEphemeralStore(memorystore.NewKV(), EphemeralMemory))
	ctx := context.Background()

	email := "abandon@example.com"
	if _, err := svc.CreatePendingRegistration(ctx, email, "abandoner", "argon2id$hash", 0); err != nil {
		t.Fatalf("CreatePendingRegistration failed: %v", err)
	}
	if pr, _ := svc.GetPendingRegistrationByEmail(ctx, email); pr == nil {
		t.Fatalf("expected pending registration before delete")
	}

	if err := svc.DeletePendingRegistrationByEmail(ctx, email); err != nil {
		t.Fatalf("DeletePendingRegistrationByEmail failed: %v", err)
	}
	if pr, _ := svc.GetPendingRegistrationByEmail(ctx, email); pr != nil {
		t.Fatalf("expected pending registration to be deleted")
	}

	// Deleting again (or when none exists) must be a no-op, not an error.
	if err := svc.DeletePendingRegistrationByEmail(ctx, email); err != nil {
		t.Fatalf("DeletePendingRegistrationByEmail no-op failed: %v", err)
	}
}

func TestDeletePendingPhoneRegistrationByPhone(t *testing.T) {
	svc := NewService(Options{RegistrationVerification: RegistrationVerificationRequired}, Keyset{}, WithEphemeralStore(memorystore.NewKV(), EphemeralMemory))
	ctx := context.Background()

	phone := "+14155550123"
	if _, err := svc.CreatePendingPhoneRegistration(ctx, phone, "phoneabandoner", "argon2id$hash"); err != nil {
		t.Fatalf("CreatePendingPhoneRegistration failed: %v", err)
	}
	if pr, _ := svc.GetPendingPhoneRegistrationByPhone(ctx, phone); pr == nil {
		t.Fatalf("expected pending phone registration before delete")
	}

	if err := svc.DeletePendingPhoneRegistrationByPhone(ctx, phone); err != nil {
		t.Fatalf("DeletePendingPhoneRegistrationByPhone failed: %v", err)
	}
	if pr, _ := svc.GetPendingPhoneRegistrationByPhone(ctx, phone); pr != nil {
		t.Fatalf("expected pending phone registration to be deleted")
	}
}
