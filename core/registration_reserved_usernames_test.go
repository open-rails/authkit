package core

import (
	"context"
	"strings"
	"testing"
)

func TestCreateUser_RejectsReservedUsername(t *testing.T) {
	t.Parallel()

	svc := NewService(Options{}, Keyset{})
	if _, err := svc.CreateUser(context.Background(), "", "superuser"); err == nil || err.Error() != "username_reserved" {
		t.Fatalf("expected username_reserved, got %v", err)
	}
}

func TestCreatePendingRegistration_RejectsReservedUsername(t *testing.T) {
	t.Parallel()

	svc := NewService(Options{}, Keyset{})
	if _, err := svc.CreatePendingRegistration(context.Background(), "test@example.com", "sudo", "hash", 0); err == nil || err.Error() != "username_reserved" {
		t.Fatalf("expected username_reserved, got %v", err)
	}
}

func TestCreatePendingPhoneRegistration_RejectsReservedUsername(t *testing.T) {
	t.Parallel()

	svc := NewService(Options{}, Keyset{})
	if _, err := svc.CreatePendingPhoneRegistration(context.Background(), "+15551234567", "admin", "hash"); err == nil || err.Error() != "username_reserved" {
		t.Fatalf("expected username_reserved, got %v", err)
	}
}

func TestGenerateAvailableUsername_SkipsReservedBase(t *testing.T) {
	t.Parallel()

	svc := NewService(Options{}, Keyset{})
	got := svc.GenerateAvailableUsername(context.Background(), "superuser")
	if strings.EqualFold(got, "superuser") {
		t.Fatalf("expected a non-reserved username, got %q", got)
	}
	if IsReservedUsername(got) {
		t.Fatalf("expected non-reserved candidate, got %q", got)
	}
}
