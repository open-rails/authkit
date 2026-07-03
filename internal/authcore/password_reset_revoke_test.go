package authcore

import (
	"context"
	"testing"
	"time"

	"github.com/open-rails/authkit/jwtkit"
)

// #199: confirming a password reset must leave ZERO live sessions — an attacker
// holding a stolen refresh token must be evicted by the very reset that rotates
// the password. The hash upsert and the revoke-all now commit in ONE transaction
// (finishPasswordReset), so the reset can never report success while pre-reset
// sessions survive.
func TestConfirmPasswordReset_RevokesAllSessions(t *testing.T) {
	pool := testPG(t)
	ks, err := jwtkit.NewGeneratedKeySource()
	if err != nil {
		t.Fatalf("gen keys: %v", err)
	}
	svc, err := NewFromConfig(Config{
		Token: TokenConfig{
			Issuer:            "https://issuer.test",
			IssuedAudiences:   []string{"app"},
			ExpectedAudiences: []string{"app"},
		},
		Keys: KeysConfig{Source: ks},
	}, pool)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	ctx := context.Background()
	uid := mkRefreshTestUser(t, ctx, svc, "pwreset199")

	// Two live sessions — the "attacker" scenario is any pre-reset session surviving.
	for i := 0; i < 2; i++ {
		if _, _, _, err := svc.IssueRefreshSession(ctx, uid, "ua", nil); err != nil {
			t.Fatalf("IssueRefreshSession: %v", err)
		}
	}
	before, err := svc.ListUserSessions(ctx, uid)
	if err != nil || len(before) != 2 {
		t.Fatalf("pre-reset sessions = %d (err=%v), want 2", len(before), err)
	}

	// Plant a reset token and confirm the reset.
	const token = "reset-token-199"
	if err := svc.storePasswordReset(ctx, sha256Hex(token), uid, time.Minute); err != nil {
		t.Fatalf("storePasswordReset: %v", err)
	}
	gotUID, err := svc.ConfirmPasswordReset(ctx, token, "New-password-12345")
	if err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}
	if gotUID != uid {
		t.Fatalf("ConfirmPasswordReset user = %q, want %q", gotUID, uid)
	}

	// Every pre-reset session is gone, and the new password is live.
	after, err := svc.ListUserSessions(ctx, uid)
	if err != nil {
		t.Fatalf("ListUserSessions after reset: %v", err)
	}
	if len(after) != 0 {
		t.Fatalf("sessions surviving the reset = %d, want 0 (%+v)", len(after), after)
	}
	if !svc.VerifyUserPassword(ctx, uid, "New-password-12345") {
		t.Fatal("new password does not verify after reset")
	}
}
