package authcore

import (
	"context"
	"errors"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
)

// failingEphemeralStore is a stub EphemeralStore that always returns an error on Set,
// simulating a Redis outage or similar ephemeral-store write failure.
type failingEphemeralStore struct{}

func (f *failingEphemeralStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	return nil, false, nil
}
func (f *failingEphemeralStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return errors.New("ephemeral store unavailable: simulated write failure")
}
func (f *failingEphemeralStore) Del(ctx context.Context, key string) error {
	return nil
}
func (f *failingEphemeralStore) Consume(ctx context.Context, key string) ([]byte, bool, error) {
	return nil, false, nil
}
func (f *failingEphemeralStore) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return 0, errors.New("ephemeral store unavailable: simulated write failure")
}

func TestVerificationMessageValidate(t *testing.T) {
	if err := (VerificationMessage{}).Validate(); err == nil {
		t.Fatal("expected validation error when both code and link URL are missing")
	}
	if err := (VerificationMessage{Code: "123456"}).Validate(); err != nil {
		t.Fatalf("unexpected validation error for code-only message: %v", err)
	}
	if err := (VerificationMessage{LinkURL: "https://example.test/verify?token=token"}).Validate(); err != nil {
		t.Fatalf("unexpected validation error for link-only message: %v", err)
	}
}

func TestValidateVerificationConfiguration(t *testing.T) {
	required := mustNewService(t, Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired}}, Keyset{})
	if err := required.ValidateVerificationConfiguration(); err == nil {
		t.Fatal("expected error when registration verification is required without senders")
	}

	none := mustNewService(t, Config{Registration: RegistrationConfig{Verification: RegistrationVerificationNone}}, Keyset{})
	if err := none.ValidateVerificationConfiguration(); err != nil {
		t.Fatalf("unexpected error for none policy: %v", err)
	}

	optional := mustNewService(t, Config{Registration: RegistrationConfig{Verification: RegistrationVerificationOptional}}, Keyset{})
	if err := optional.ValidateVerificationConfiguration(); err != nil {
		t.Fatalf("unexpected error for optional policy: %v", err)
	}
}

func TestPendingRegistrationStoresCodeAndLinkTokens(t *testing.T) {
	svc := mustNewService(t, Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired}}, Keyset{}, WithEphemeralStore(memorystore.NewKV()))

	ctx := context.Background()
	code, err := svc.CreatePendingRegistrationWithLanguage(ctx, "test@example.com", "tester", "argon2id$hash", 0, "")
	if err != nil {
		t.Fatalf("CreatePendingRegistration failed: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}

	data, ok := svc.findPendingChangeByTarget(ctx, KindRegisterEmail, "test@example.com")
	if !ok {
		t.Fatal("pending registration not stored by target")
	}
	if data.CodeHash != sha256Hex(code) {
		t.Fatal("record must carry the code hash")
	}
	if data.LinkHash == "" {
		t.Fatal("record must carry a link hash")
	}
	if key, ok := svc.consumeLink(ctx, pendingChangeLinkKey(KindRegisterEmail, data.LinkHash)); !ok || key != data.key() {
		t.Fatal("link pointer must resolve to the pending registration")
	}
}

func TestPendingPhoneRegistrationStoresCodeAndLinkTokens(t *testing.T) {
	svc := mustNewService(t, Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired}}, Keyset{}, WithEphemeralStore(memorystore.NewKV()))

	ctx := context.Background()
	code, err := svc.CreatePendingPhoneRegistrationWithLanguage(ctx, "+15551234567", "tester", "argon2id$hash", "")
	if err != nil {
		t.Fatalf("CreatePendingPhoneRegistration failed: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}

	data, ok := svc.findPendingChangeByTarget(ctx, KindRegisterPhone, "+15551234567")
	if !ok {
		t.Fatal("pending phone registration not stored by target")
	}
	if data.CodeHash != sha256Hex(code) || data.LinkHash == "" {
		t.Fatal("record must carry both the code hash and a link hash")
	}
}

// TestSendEmailVerificationStoreFailureSurfaces asserts that when the ephemeral
// store fails to write, sendEmailVerificationToUser returns the store error rather
// than silently swallowing it (regression for the return-nil bug).
func TestSendEmailVerificationStoreFailureSurfaces(t *testing.T) {
	svc := mustNewService(t,
		Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired}},
		Keyset{},
		WithEphemeralStore(&failingEphemeralStore{}),
	)

	email := "user@example.test"
	u := &User{
		ID:            "user-store-fail",
		Email:         &email,
		EmailVerified: false,
	}

	err := svc.sendEmailVerificationToUser(context.Background(), u, 0)
	if err == nil {
		t.Fatal("expected non-nil error when ephemeral store write fails, got nil")
	}
}

// TestSendPhoneVerificationStoreFailureSurfaces asserts that when the ephemeral
// store fails to write, SendPhoneVerificationToUser returns the store error rather
// than silently swallowing it (regression for the return-nil bug).
func TestSendPhoneVerificationStoreFailureSurfaces(t *testing.T) {
	svc := mustNewService(t,
		Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired}},
		Keyset{},
		WithEphemeralStore(&failingEphemeralStore{}),
	)

	err := svc.SendPhoneVerificationToUser(context.Background(), "+15551234567", "user-store-fail", 0)
	if err == nil {
		t.Fatal("expected non-nil error when ephemeral store write fails, got nil")
	}
}
