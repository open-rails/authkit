package core

import (
	"context"
	"testing"

	memorystore "github.com/PaulFidika/authkit/storage/memory"
)

func TestPendingRegistrationMemoryStore(t *testing.T) {
	svc := NewService(Options{}, Keyset{})
	svc.WithEphemeralStore(memorystore.NewKV(), EphemeralMemory)

	email := "test@example.com"
	username := "tester"
	hash := "argon2id$hash"

	if _, err := svc.CreatePendingRegistration(context.Background(), email, username, hash, 0); err != nil {
		t.Fatalf("CreatePendingRegistration failed: %v", err)
	}

	pr, err := svc.GetPendingRegistrationByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("GetPendingRegistrationByEmail failed: %v", err)
	}
	if pr == nil {
		t.Fatalf("expected pending registration")
	}
	if pr.Username != username {
		t.Fatalf("expected username %q, got %q", username, pr.Username)
	}
	if pr.PasswordHash != hash {
		t.Fatalf("expected password hash to match")
	}
}
