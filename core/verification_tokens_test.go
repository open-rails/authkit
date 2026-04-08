package core

import (
	"context"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/storage/memory"
)

func TestVerificationMessageValidate(t *testing.T) {
	if err := (VerificationMessage{}).Validate(); err == nil {
		t.Fatal("expected validation error when both code and link token are missing")
	}
	if err := (VerificationMessage{Code: "123456"}).Validate(); err != nil {
		t.Fatalf("unexpected validation error for code-only message: %v", err)
	}
	if err := (VerificationMessage{LinkToken: "token"}).Validate(); err != nil {
		t.Fatalf("unexpected validation error for link-only message: %v", err)
	}
}

func TestValidateVerificationConfiguration(t *testing.T) {
	required := NewService(Options{RegistrationVerification: RegistrationVerificationRequired}, Keyset{})
	if err := required.ValidateVerificationConfiguration(); err == nil {
		t.Fatal("expected error when registration verification is required without senders")
	}

	none := NewService(Options{RegistrationVerification: RegistrationVerificationNone}, Keyset{})
	if err := none.ValidateVerificationConfiguration(); err != nil {
		t.Fatalf("unexpected error for none policy: %v", err)
	}

	optional := NewService(Options{RegistrationVerification: RegistrationVerificationOptional}, Keyset{})
	if err := optional.ValidateVerificationConfiguration(); err != nil {
		t.Fatalf("unexpected error for optional policy: %v", err)
	}
}

func TestPendingRegistrationStoresCodeAndLinkTokens(t *testing.T) {
	svc := NewService(Options{RegistrationVerification: RegistrationVerificationRequired}, Keyset{})
	svc.WithEphemeralStore(memorystore.NewKV(), EphemeralMemory)

	ctx := context.Background()
	code, err := svc.CreatePendingRegistration(ctx, "test@example.com", "tester", "argon2id$hash", 0)
	if err != nil {
		t.Fatalf("CreatePendingRegistration failed: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}

	data, ok, err := svc.loadPendingRegistration(ctx, sha256Hex(code))
	if err != nil || !ok {
		t.Fatalf("pending registration not stored by code hash: ok=%v err=%v", ok, err)
	}
	if len(data.TokenHashes) < 2 {
		t.Fatalf("expected both code+link token hashes, got %d", len(data.TokenHashes))
	}

	foundLink := false
	for _, h := range data.TokenHashes {
		if h == sha256Hex(code) {
			continue
		}
		if _, ok, err := svc.loadPendingRegistration(ctx, h); err == nil && ok {
			foundLink = true
			break
		}
	}
	if !foundLink {
		t.Fatal("expected a second pending-registration token hash for link verification")
	}
}

func TestPendingPhoneRegistrationStoresCodeAndLinkTokens(t *testing.T) {
	svc := NewService(Options{RegistrationVerification: RegistrationVerificationRequired}, Keyset{})
	svc.WithEphemeralStore(memorystore.NewKV(), EphemeralMemory)

	ctx := context.Background()
	code, err := svc.CreatePendingPhoneRegistration(ctx, "+15551234567", "tester", "argon2id$hash")
	if err != nil {
		t.Fatalf("CreatePendingPhoneRegistration failed: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}

	data, ok, err := svc.loadPendingPhoneRegistration(ctx, sha256Hex(code))
	if err != nil || !ok {
		t.Fatalf("pending phone registration not stored by code hash: ok=%v err=%v", ok, err)
	}
	if len(data.TokenHashes) < 2 {
		t.Fatalf("expected both code+link token hashes, got %d", len(data.TokenHashes))
	}
}

func TestPasswordResetSessionOneTimeConsume(t *testing.T) {
	svc := NewService(Options{}, Keyset{})
	svc.WithEphemeralStore(memorystore.NewKV(), EphemeralMemory)

	ctx := context.Background()
	sessionHash := sha256Hex("session-token")
	if err := svc.storePasswordResetSession(ctx, sessionHash, "user-1", 15*time.Minute); err != nil {
		t.Fatalf("storePasswordResetSession failed: %v", err)
	}

	userID, err := svc.consumePasswordResetSession(ctx, sessionHash)
	if err != nil {
		t.Fatalf("consumePasswordResetSession failed: %v", err)
	}
	if userID != "user-1" {
		t.Fatalf("unexpected user id: %q", userID)
	}

	if _, err := svc.consumePasswordResetSession(ctx, sessionHash); err == nil {
		t.Fatal("expected second consume to fail for one-time reset session")
	}
}
