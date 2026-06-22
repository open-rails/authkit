package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// #89 (no DB): enforce-as-desired-state is rejected with reset_required, valid
// with plaintext, and reset_required alone remains valid.
func TestValidateBootstrapUserPasswordEnforce(t *testing.T) {
	if err := validateBootstrapUserPassword(BootstrapUserPassword{ResetRequired: true, Enforce: true}); !errors.Is(err, ErrInvalidBootstrapManifest) {
		t.Fatalf("enforce+reset_required err=%v, want ErrInvalidBootstrapManifest", err)
	}
	if err := validateBootstrapUserPassword(BootstrapUserPassword{Plaintext: "bootstrap-password-1", Enforce: true}); err != nil {
		t.Fatalf("enforce+plaintext should be valid, got %v", err)
	}
	if err := validateBootstrapUserPassword(BootstrapUserPassword{ResetRequired: true}); err != nil {
		t.Fatalf("reset_required alone should be valid, got %v", err)
	}
}

// #89 (DB): a manifest password is SEED-ONCE by default — a password rotated out
// of band after the initial seed survives a later reconcile — but enforce:true
// re-asserts the manifest value. Skips without AUTHKIT_TEST_DATABASE_URL.
func TestReconcileBootstrapManifestPasswordSeedOnce(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))

	username := fmt.Sprintf("seed-once-%d", time.Now().UnixNano())
	const seeded = "bootstrap-password-1"
	const rotated = "rotated-password-2"

	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{
		Username:      username,
		Email:         username + "@example.com",
		EmailVerified: true,
		Password:      &BootstrapUserPassword{Plaintext: seeded},
	}}}

	// First reconcile creates the user and seeds the password.
	if _, err := svc.ReconcileBootstrapManifest(ctx, manifest, nil, BootstrapReconcileOptions{}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	user, err := svc.getUserByUsername(ctx, username)
	if err != nil || user == nil {
		t.Fatalf("user lookup after seed: %v", err)
	}
	t.Cleanup(func() { _ = svc.SoftDeleteUser(context.Background(), user.ID) })

	// Operator rotates the password out of band.
	if err := svc.AdminSetPassword(ctx, user.ID, rotated); err != nil {
		t.Fatalf("rotate password: %v", err)
	}

	// Re-applying the SAME manifest (default, seed-once) must NOT revert it.
	if _, err := svc.ReconcileBootstrapManifest(ctx, manifest, nil, BootstrapReconcileOptions{}); err != nil {
		t.Fatalf("second reconcile (seed-once): %v", err)
	}
	if err := svc.CheckUserPassword(ctx, user.ID, rotated); err != nil {
		t.Fatalf("rotated password should survive seed-once reconcile, got %v", err)
	}
	if err := svc.CheckUserPassword(ctx, user.ID, seeded); err == nil {
		t.Fatal("seeded password must NOT have been re-asserted under seed-once")
	}

	// With enforce:true the manifest value is re-asserted (desired-state).
	enforce := manifest
	enforce.Users = []BootstrapManifestUser{{
		Username:      username,
		Email:         username + "@example.com",
		EmailVerified: true,
		Password:      &BootstrapUserPassword{Plaintext: seeded, Enforce: true},
	}}
	if _, err := svc.ReconcileBootstrapManifest(ctx, enforce, nil, BootstrapReconcileOptions{}); err != nil {
		t.Fatalf("enforce reconcile: %v", err)
	}
	if err := svc.CheckUserPassword(ctx, user.ID, seeded); err != nil {
		t.Fatalf("enforce should re-assert the manifest password, got %v", err)
	}
}
