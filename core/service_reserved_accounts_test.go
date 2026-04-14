package core

import (
	"context"
	"errors"
	"testing"
)

func TestClaimReservedAccountProtectsRootSlug(t *testing.T) {
	svc := NewService(Options{}, Keyset{})

	_, _, err := svc.ClaimReservedAccount(context.Background(), "root", "StrongPassword123!", nil, nil)
	if !errors.Is(err, ErrReservedAccountProtected) {
		t.Fatalf("expected ErrReservedAccountProtected, got: %v", err)
	}
}
