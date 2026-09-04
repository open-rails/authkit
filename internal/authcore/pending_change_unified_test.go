package authcore

import (
	"context"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/internal/storage/memory"
)

func newPendingChangeTestService() *Service {
	svc := NewService(Config{Registration: RegistrationConfig{Verification: RegistrationVerificationRequired}}, Keyset{}, WithEphemeralStore(memorystore.NewKV()))
	return svc
}

// #360: the four pending-change kinds all round-trip through the single unified
// ephemeral store — found back by target (register) or by user (change), carrying
// their code hash, and fully removed on delete.
func TestPendingChangeUnifiedRoundTrip(t *testing.T) {
	ctx := context.Background()

	t.Run("register_email", func(t *testing.T) {
		svc := newPendingChangeTestService()
		rec := pendingChange{Kind: KindRegisterEmail, Target: "Reg@Example.com", Username: "reguser", PasswordHash: "argon2id$h", CodeHash: sha256Hex("code1")}
		if err := svc.storePendingChange(ctx, rec, 0); err != nil {
			t.Fatalf("store: %v", err)
		}
		got, ok := svc.findPendingChangeByTarget(ctx, KindRegisterEmail, "reg@example.com")
		if !ok || got.Username != "reguser" || got.PasswordHash != "argon2id$h" || got.CodeHash != sha256Hex("code1") {
			t.Fatalf("findByTarget mismatch: ok=%v rec=%+v", ok, got)
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
		// Deleting when nothing is pending must be a no-op, not an error.
		if err := svc.DeletePendingRegistrationByEmail(ctx, "reg@example.com"); err != nil {
			t.Fatalf("delete of absent pending registration must be a no-op: %v", err)
		}
	})

	t.Run("register_phone", func(t *testing.T) {
		svc := newPendingChangeTestService()
		rec := pendingChange{Kind: KindRegisterPhone, Target: "+14155550111", Username: "phoneuser", PasswordHash: "argon2id$h", CodeHash: sha256Hex("code2")}
		if err := svc.storePendingChange(ctx, rec, 0); err != nil {
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
		rec := pendingChange{Kind: KindChangeEmail, Target: "new@example.com", UserID: "user-1", CodeHash: sha256Hex("code3")}
		if err := svc.storePendingChange(ctx, rec, 0); err != nil {
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
		rec := pendingChange{Kind: KindChangePhone, Target: "+14155550222", UserID: "user-2", CodeHash: sha256Hex("code4")}
		if err := svc.storePendingChange(ctx, rec, 0); err != nil {
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

	_ = svc.storePendingChange(ctx, pendingChange{Kind: KindChangeEmail, Target: "a@example.com", UserID: "u1", CodeHash: sha256Hex("c1")}, 0)
	_ = svc.storePendingChange(ctx, pendingChange{Kind: KindChangePhone, Target: "+14155550333", UserID: "u1", CodeHash: sha256Hex("c2")}, 0)

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

// #360: a pending change expires by its TTL — the record and its link pointer are
// gone once the TTL elapses (ephemeral-store TTL is what replaces the old
// postgres cleanup worker for pending state).
func TestPendingChangeExpiresByTTL(t *testing.T) {
	ctx := context.Background()
	svc := newPendingChangeTestService()

	if err := svc.storePendingChange(ctx, pendingChange{Kind: KindChangeEmail, Target: "exp@example.com", UserID: "u-exp", CodeHash: sha256Hex("expcode"), LinkHash: sha256Hex("explink")}, 20*time.Millisecond); err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, ok := svc.findPendingChangeByUser(ctx, KindChangeEmail, "u-exp"); !ok {
		t.Fatal("should be present before TTL elapses")
	}

	time.Sleep(60 * time.Millisecond)

	if _, ok := svc.findPendingChangeByUser(ctx, KindChangeEmail, "u-exp"); ok {
		t.Fatal("record should have expired")
	}
	if _, ok := svc.consumeLink(ctx, pendingChangeLinkKey(KindChangeEmail, sha256Hex("explink"))); ok {
		t.Fatal("link pointer should have expired")
	}
}

// #360: re-requesting a pending change for the same identity supersedes the prior
// record (old code and old link no longer resolve).
func TestPendingChangeSupersedesPrior(t *testing.T) {
	ctx := context.Background()
	svc := newPendingChangeTestService()

	_ = svc.storePendingChange(ctx, pendingChange{Kind: KindChangeEmail, Target: "x@example.com", UserID: "u9", CodeHash: sha256Hex("old"), LinkHash: sha256Hex("oldlink")}, 0)
	_ = svc.storePendingChange(ctx, pendingChange{Kind: KindChangeEmail, Target: "x@example.com", UserID: "u9", CodeHash: sha256Hex("new"), LinkHash: sha256Hex("newlink")}, 0)

	rec, ok := svc.findPendingChangeByUser(ctx, KindChangeEmail, "u9")
	if !ok || rec.CodeHash != sha256Hex("new") {
		t.Fatal("new code should resolve")
	}
	if _, ok := svc.consumeLink(ctx, pendingChangeLinkKey(KindChangeEmail, sha256Hex("oldlink"))); ok {
		t.Fatal("old link should be superseded")
	}
	if key, ok := svc.consumeLink(ctx, pendingChangeLinkKey(KindChangeEmail, sha256Hex("newlink"))); !ok || key != rec.key() {
		t.Fatal("new link should resolve to the record")
	}
}
