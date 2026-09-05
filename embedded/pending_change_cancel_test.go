package embedded

import (
	"context"
	"testing"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
)

// #356: a pending (unverified) email registration must make that email report as
// taken by the availability check — not only committed/verified users.
func TestPendingRegistrationMakesEmailUnavailable(t *testing.T) {
	svc := mustNewService(t, Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired, AllowMissingSenders: true}}, Keyset{}, WithEphemeralStore(memorystore.NewKV()))
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
	svc := mustNewService(t, Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired, AllowMissingSenders: true}}, Keyset{}, WithEphemeralStore(memorystore.NewKV()))
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
