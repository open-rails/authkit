package core

import (
	"context"
	"testing"
)

func TestCreateUser_DoesNotHardcodeReservedSlugRejection(t *testing.T) {
	t.Parallel()

	svc := NewService(Options{}, Keyset{})
	if _, err := svc.CreateUser(context.Background(), "", "superuser"); err != nil {
		t.Fatalf("expected no hardcoded reserved check, got %v", err)
	}
}

func TestCreatePendingRegistration_DoesNotReturnUsernameReserved(t *testing.T) {
	t.Parallel()

	svc := NewService(Options{}, Keyset{})
	if _, err := svc.CreatePendingRegistration(context.Background(), "test@example.com", "sudo", "hash", 0); err != nil && err.Error() == "username_reserved" {
		t.Fatalf("expected DB-backed conflict behavior, got hardcoded username_reserved")
	}
}

func TestCreatePendingPhoneRegistration_DoesNotReturnUsernameReserved(t *testing.T) {
	t.Parallel()

	svc := NewService(Options{}, Keyset{})
	if _, err := svc.CreatePendingPhoneRegistration(context.Background(), "+15551234567", "admin", "hash"); err != nil && err.Error() == "username_reserved" {
		t.Fatalf("expected DB-backed conflict behavior, got hardcoded username_reserved")
	}
}

func TestGenerateAvailableUsername_CanReturnReservedBaseWithoutDBSeed(t *testing.T) {
	t.Parallel()

	svc := NewService(Options{}, Keyset{})
	got := svc.GenerateAvailableUsername(context.Background(), "superuser")
	if got != "superuser" {
		t.Fatalf("expected base username when DB has no seeded rows, got %q", got)
	}
}
