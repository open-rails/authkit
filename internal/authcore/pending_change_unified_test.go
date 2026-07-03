package authcore

import (
	"context"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/storage/memory"
)

func newPendingChangeTestService() *Service {
	svc := NewService(Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired}}, Keyset{}, WithEphemeralStore(memorystore.NewKV()))
	return svc
}

// #360: the four pending-change kinds all round-trip through the single unified
// ephemeral store — stored under their token hash, found back by target (register)
// or by user (change), and fully removed on delete.
func TestPendingChangeUnifiedRoundTrip(t *testing.T) {
	ctx := context.Background()

	t.Run("register_email", func(t *testing.T) {
		svc := newPendingChangeTestService()
		rec := pendingChange{Kind: KindRegisterEmail, Target: "Reg@Example.com", Username: "reguser", PasswordHash: "argon2id$h"}
		if err := svc.storePendingChange(ctx, rec, map[string]time.Duration{sha256Hex("code1"): defaultEmailVerificationTTL}); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, ok := svc.findPendingChangeByTarget(ctx, KindRegisterEmail, "reg@example.com")
		if !ok || got.Username != "reguser" || got.PasswordHash != "argon2id$h" {
			t.Fatalf("findByTarget mismatch: ok=%v rec=%+v", ok, got)
		}
		if loaded, ok, _ := svc.loadPendingChangeByToken(ctx, sha256Hex("code1")); !ok || loaded.Kind != KindRegisterEmail {
			t.Fatalf("loadByToken failed: ok=%v kind=%v", ok, loaded.Kind)
		}
		if !svc.pendingChangeTargetTaken(ctx, KindRegisterEmail, "reg@example.com") {
			t.Fatal("target should be taken")
		}
		if !svc.pendingChangeUsernameTaken(ctx, "reguser") {
			t.Fatal("username should be taken")
		}
		svc.deletePendingChangeByTarget(ctx, KindRegisterEmail, "reg@example.com")
		if _, ok := svc.findPendingChangeByTarget(ctx, KindRegisterEmail, "reg@example.com"); ok {
			t.Fatal("expected cleared after delete")
		}
		if svc.pendingChangeUsernameTaken(ctx, "reguser") {
			t.Fatal("username index should be cleared after delete")
		}
	})

	t.Run("register_phone", func(t *testing.T) {
		svc := newPendingChangeTestService()
		rec := pendingChange{Kind: KindRegisterPhone, Target: "+14155550111", Username: "phoneuser", PasswordHash: "argon2id$h"}
		if err := svc.storePendingChange(ctx, rec, map[string]time.Duration{sha256Hex("code2"): defaultPhoneVerificationTTL}); err != nil {
			t.Fatalf("store: %v", err)
		}
		if got, ok := svc.findPendingChangeByTarget(ctx, KindRegisterPhone, "+14155550111"); !ok || got.Username != "phoneuser" {
			t.Fatalf("findByTarget mismatch: ok=%v rec=%+v", ok, got)
		}
		svc.deletePendingChangeByTarget(ctx, KindRegisterPhone, "+14155550111")
		if _, ok := svc.findPendingChangeByTarget(ctx, KindRegisterPhone, "+14155550111"); ok {
			t.Fatal("expected cleared after delete")
		}
	})

	t.Run("change_email", func(t *testing.T) {
		svc := newPendingChangeTestService()
		rec := pendingChange{Kind: KindChangeEmail, Target: "new@example.com", UserID: "user-1"}
		if err := svc.storePendingChange(ctx, rec, map[string]time.Duration{sha256Hex("code3"): defaultEmailVerificationTTL}); err != nil {
			t.Fatalf("store: %v", err)
		}
		if got, ok := svc.findPendingChangeByUser(ctx, KindChangeEmail, "user-1"); !ok || got.Target != "new@example.com" {
			t.Fatalf("findByUser mismatch: ok=%v rec=%+v", ok, got)
		}
		svc.deletePendingChangeByUser(ctx, KindChangeEmail, "user-1")
		if _, ok := svc.findPendingChangeByUser(ctx, KindChangeEmail, "user-1"); ok {
			t.Fatal("expected cleared after delete")
		}
	})

	t.Run("change_phone", func(t *testing.T) {
		svc := newPendingChangeTestService()
		rec := pendingChange{Kind: KindChangePhone, Target: "+14155550222", UserID: "user-2"}
		if err := svc.storePendingChange(ctx, rec, map[string]time.Duration{sha256Hex("code4"): defaultPhoneVerificationTTL}); err != nil {
			t.Fatalf("store: %v", err)
		}
		if got, ok := svc.findPendingChangeByUser(ctx, KindChangePhone, "user-2"); !ok || got.Target != "+14155550222" {
			t.Fatalf("findByUser mismatch: ok=%v rec=%+v", ok, got)
		}
		svc.deletePendingChangeByUser(ctx, KindChangePhone, "user-2")
		if _, ok := svc.findPendingChangeByUser(ctx, KindChangePhone, "user-2"); ok {
			t.Fatal("expected cleared after delete")
		}
	})
}

// #360: different kinds sharing the same user/identifier never collide — a
// change_email lookup must not return a register_email record and vice versa.
func TestPendingChangeKindsAreIsolated(t *testing.T) {
	ctx := context.Background()
	svc := newPendingChangeTestService()

	_ = svc.storePendingChange(ctx, pendingChange{Kind: KindChangeEmail, Target: "a@example.com", UserID: "u1"},
		map[string]time.Duration{sha256Hex("c1"): defaultEmailVerificationTTL})
	_ = svc.storePendingChange(ctx, pendingChange{Kind: KindChangePhone, Target: "+14155550333", UserID: "u1"},
		map[string]time.Duration{sha256Hex("c2"): defaultPhoneVerificationTTL})

	if _, ok := svc.findPendingChangeByUser(ctx, KindChangeEmail, "u1"); !ok {
		t.Fatal("change_email should be found for u1")
	}
	if _, ok := svc.findPendingChangeByUser(ctx, KindChangePhone, "u1"); !ok {
		t.Fatal("change_phone should be found for u1")
	}
	// Cancelling one kind leaves the other intact.
	svc.deletePendingChangeByUser(ctx, KindChangeEmail, "u1")
	if _, ok := svc.findPendingChangeByUser(ctx, KindChangeEmail, "u1"); ok {
		t.Fatal("change_email should be gone")
	}
	if _, ok := svc.findPendingChangeByUser(ctx, KindChangePhone, "u1"); !ok {
		t.Fatal("change_phone must survive deletion of change_email")
	}
}

// #360: a pending change expires by its token TTL — both the token record and
// its lookup indexes are gone once the TTL elapses (ephemeral-store TTL is what
// replaces the old postgres cleanup worker for pending state).
func TestPendingChangeExpiresByTTL(t *testing.T) {
	ctx := context.Background()
	svc := newPendingChangeTestService()

	if err := svc.storePendingChange(ctx, pendingChange{Kind: KindChangeEmail, Target: "exp@example.com", UserID: "u-exp"},
		map[string]time.Duration{sha256Hex("expcode"): 20 * time.Millisecond}); err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, ok := svc.findPendingChangeByUser(ctx, KindChangeEmail, "u-exp"); !ok {
		t.Fatal("should be present before TTL elapses")
	}

	time.Sleep(60 * time.Millisecond)

	if _, ok, _ := svc.loadPendingChangeByToken(ctx, sha256Hex("expcode")); ok {
		t.Fatal("token record should have expired")
	}
	if _, ok := svc.findPendingChangeByUser(ctx, KindChangeEmail, "u-exp"); ok {
		t.Fatal("user index should have expired")
	}
}

// #360: re-requesting a pending change for the same target supersedes the prior
// record (old token no longer resolves).
func TestPendingChangeSupersedesPrior(t *testing.T) {
	ctx := context.Background()
	svc := newPendingChangeTestService()

	_ = svc.storePendingChange(ctx, pendingChange{Kind: KindChangeEmail, Target: "x@example.com", UserID: "u9"},
		map[string]time.Duration{sha256Hex("old"): defaultEmailVerificationTTL})
	_ = svc.storePendingChange(ctx, pendingChange{Kind: KindChangeEmail, Target: "x@example.com", UserID: "u9"},
		map[string]time.Duration{sha256Hex("new"): defaultEmailVerificationTTL})

	if _, ok, _ := svc.loadPendingChangeByToken(ctx, sha256Hex("old")); ok {
		t.Fatal("old token should be superseded")
	}
	if _, ok, _ := svc.loadPendingChangeByToken(ctx, sha256Hex("new")); !ok {
		t.Fatal("new token should resolve")
	}
}
