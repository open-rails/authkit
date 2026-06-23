package core

import (
	"context"
	"testing"
)

func TestLegacyTwoFactorSettingsExposeDefaultFactor(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))

	email := "legacy-2fa-factor@test.example"
	username := "legacy2fafactor"
	user, err := svc.CreateUser(ctx, email, username)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	if _, err := pool.Exec(ctx, `DELETE FROM profiles.two_factor_factors WHERE user_id=$1::uuid`, user.ID); err != nil {
		t.Fatalf("delete factor rows: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO profiles.two_factor_settings (user_id, enabled, method, phone_number, backup_codes)
		VALUES ($1::uuid, true, 'sms', '+15551234567', ARRAY[$2]::text[])
		ON CONFLICT (user_id) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			method = EXCLUDED.method,
			phone_number = EXCLUDED.phone_number,
			backup_codes = EXCLUDED.backup_codes,
			totp_secret = NULL,
			last_totp_step = NULL,
			updated_at = NOW()
	`, user.ID, sha256Hex("BACKUP01")); err != nil {
		t.Fatalf("insert legacy settings: %v", err)
	}

	settings, err := svc.Get2FASettings(ctx, user.ID)
	if err != nil {
		t.Fatalf("get settings: %v", err)
	}
	if !settings.Enabled || settings.Method != "sms" {
		t.Fatalf("settings = %+v, want enabled sms", settings)
	}
	if len(settings.Factors) != 1 {
		t.Fatalf("factors len = %d, want 1", len(settings.Factors))
	}
	factor := settings.Factors[0]
	if factor.ID != "" || factor.Method != "sms" || !factor.IsDefault || !factor.Enabled {
		t.Fatalf("legacy factor = %+v, want synthesized default sms factor", factor)
	}
	if factor.PhoneNumber == nil || *factor.PhoneNumber != "+15551234567" {
		t.Fatalf("legacy factor phone = %v, want +15551234567", factor.PhoneNumber)
	}
}
