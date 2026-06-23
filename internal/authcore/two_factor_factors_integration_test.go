package authcore

import (
	"context"
	"testing"
)

// #125: mfa_settings no longer mirrors per-factor data; the displayed
// method/phone are derived from the default row in mfa_factors.
func TestMFASettingsDeriveFromDefaultFactor(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))

	email := "derive-2fa-factor@test.example"
	username := "derive2fafactor"
	user, err := svc.CreateUser(ctx, email, username)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	phone := "+15551234567"
	if _, err := svc.Enable2FA(ctx, user.ID, "sms", &phone); err != nil {
		t.Fatalf("enable sms 2FA: %v", err)
	}

	settings, err := svc.Get2FASettings(ctx, user.ID)
	if err != nil {
		t.Fatalf("get settings: %v", err)
	}
	if !settings.Enabled || settings.Method != "sms" {
		t.Fatalf("settings = %+v, want enabled sms (derived from default factor)", settings)
	}
	if len(settings.Factors) != 1 {
		t.Fatalf("factors len = %d, want 1", len(settings.Factors))
	}
	factor := settings.Factors[0]
	// The factor is a real persisted row now (has an id), not synthesized.
	if factor.ID == "" || factor.Method != "sms" || !factor.IsDefault {
		t.Fatalf("factor = %+v, want real default sms factor with id", factor)
	}
	if factor.PhoneNumber == nil || *factor.PhoneNumber != phone {
		t.Fatalf("factor phone = %v, want %s", factor.PhoneNumber, phone)
	}
}

// #125: removing a factor is a HARD delete — the row is physically gone, leaves
// no enabled=false tombstone, and re-enrolling the same method does not
// accumulate dead rows.
func TestMFAFactorHardDelete(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))

	user, err := svc.CreateUser(ctx, "harddelete-2fa@test.example", "harddelete2fa")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	countFactors := func() int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM profiles.mfa_factors WHERE user_id=$1::uuid`, user.ID).Scan(&n); err != nil {
			t.Fatalf("count factors: %v", err)
		}
		return n
	}

	phone := "+15550000001"
	if _, err := svc.Enable2FA(ctx, user.ID, "sms", &phone); err != nil {
		t.Fatalf("enable sms: %v", err)
	}
	if _, err := svc.Enable2FA(ctx, user.ID, "email", nil); err != nil {
		t.Fatalf("enable email: %v", err)
	}
	if n := countFactors(); n != 2 {
		t.Fatalf("after enroll: %d factor rows, want 2", n)
	}

	// Find and delete the SMS factor (the first/default).
	factors, err := svc.List2FAFactors(ctx, user.ID)
	if err != nil {
		t.Fatalf("list factors: %v", err)
	}
	var smsID string
	for _, f := range factors {
		if f.Method == "sms" {
			smsID = f.ID
		}
	}
	if smsID == "" {
		t.Fatalf("no sms factor found in %+v", factors)
	}
	if err := svc.Disable2FAFactor(ctx, user.ID, smsID); err != nil {
		t.Fatalf("disable (delete) sms factor: %v", err)
	}

	// HARD delete: the row is physically gone — no enabled=false tombstone.
	if n := countFactors(); n != 1 {
		t.Fatalf("after delete: %d factor rows, want 1 (no tombstone)", n)
	}
	remaining, _ := svc.List2FAFactors(ctx, user.ID)
	if len(remaining) != 1 || remaining[0].Method != "email" {
		t.Fatalf("remaining factors = %+v, want only email", remaining)
	}

	// Re-enrolling the deleted method inserts a fresh row, not a second copy.
	if _, err := svc.Enable2FA(ctx, user.ID, "sms", &phone); err != nil {
		t.Fatalf("re-enroll sms: %v", err)
	}
	if n := countFactors(); n != 2 {
		t.Fatalf("after re-enroll: %d factor rows, want 2 (no accumulated tombstone)", n)
	}
}
