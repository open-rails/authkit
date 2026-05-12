package core

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestAssignRoleBySlug_RejectsOwner(t *testing.T) {
	svc := &Service{}
	if err := svc.AssignRoleBySlug(context.Background(), "user", "owner"); err == nil {
		t.Fatalf("expected error")
	} else if err != ErrReservedRoleSlug {
		t.Fatalf("expected ErrReservedRoleSlug, got %v", err)
	}
}

func TestRemoveRoleBySlug_AdminGuardContract(t *testing.T) {
	src, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}
	text := string(src)
	for _, want := range []string{
		"ErrCannotRemoveLastAdminRole",
		"removeAdminRoleIfNotLast",
		"FOR UPDATE",
		"activeAdminCount <= 1",
		"u.deleted_at IS NULL",
		"u.banned_at IS NULL",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected service.go to contain %q", want)
		}
	}
}
