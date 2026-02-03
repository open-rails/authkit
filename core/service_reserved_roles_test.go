package core

import (
	"context"
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
