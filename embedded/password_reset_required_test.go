package embedded

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/password"
)

// TestLegacyResetRequiredPasswordPaths covers accounts migrated with
// hash_algo=HashAlgoLegacyResetRequired: every password-verify path must
// return ErrPasswordResetRequired (never a successful verify, never a generic
// unauthorized), and a completed reset (argon2id upsert) must clear the flag.
// Skips when AUTHKIT_TEST_DATABASE_URL is unset.
func TestLegacyResetRequiredPasswordPaths(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()

	signer, err := jwtkit.NewEd25519Signer("reset-required-test")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	svc := mustNewService(t, Config{Token: TokenConfig{Issuer: "https://test", IssuedAudiences: []string{"app"}, ExpectedAudiences: []string{"app"}, AccessTokenDuration: time.Hour}}, Keyset{
		Active:     signer,
		PublicKeys: map[string]crypto.PublicKey{"reset-required-test": signer.PublicKey()},
	}, WithPostgres(pool))

	const email = "legacy-reset-required@example.com"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email)
	u, err := svc.CreateUser(ctx, email, "legacyresetrequired")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })

	// Stamp an unimportable legacy hash (md5-crypt shaped) the way the doujins
	// migration does: raw value preserved for forensics, algo flagged.
	if err := svc.UpsertPasswordHash(ctx, u.ID, "$1$saltsalt$qJH7.N4xYta3aEG/dfqo/0", HashAlgoLegacyResetRequired, nil); err != nil {
		t.Fatalf("upsert legacy hash: %v", err)
	}

	// PasswordLogin surfaces the sentinel as the rejection reason on both the
	// email and the username identifier paths.
	for _, identifier := range []string{email, "legacyresetrequired"} {
		out, err := svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: identifier, Password: "anything"})
		if err != nil || out.Kind != LoginRejected || !errors.Is(out.Reason, ErrPasswordResetRequired) {
			t.Fatalf("PasswordLogin(%q) = %+v, %v; want LoginRejected/ErrPasswordResetRequired", identifier, out, err)
		}
	}
	// CheckUserPassword (step-up flows) surfaces the sentinel; the bool wrapper
	// stays false so legacy callers fail closed.
	if err := svc.CheckUserPassword(ctx, u.ID, "anything"); !errors.Is(err, ErrPasswordResetRequired) {
		t.Fatalf("CheckUserPassword err = %v, want ErrPasswordResetRequired", err)
	}
	if svc.CheckUserPassword(ctx, u.ID, "anything") == nil {
		t.Fatalf("CheckUserPassword must never succeed for a reset-required hash")
	}
	// ChangePassword verifies the old password, which the user cannot know.
	if err := svc.ChangePassword(ctx, u.ID, "anything", "brand-new-password-1", nil); !errors.Is(err, ErrPasswordResetRequired) {
		t.Fatalf("ChangePassword err = %v, want ErrPasswordResetRequired", err)
	}

	// A completed password reset overwrites the row with argon2id (same upsert
	// finishPasswordReset performs) and clears the condition.
	phc, err := password.HashArgon2id("brand-new-password-1")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := svc.UpsertPasswordHash(ctx, u.ID, phc, "argon2id", nil); err != nil {
		t.Fatalf("upsert argon2id: %v", err)
	}
	if out, err := svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: email, Password: "brand-new-password-1"}); err != nil || out.Kind != LoginSessionIssued {
		t.Fatalf("PasswordLogin after reset = %+v, %v; want LoginSessionIssued", out, err)
	}
	if err := svc.CheckUserPassword(ctx, u.ID, "brand-new-password-1"); err != nil {
		t.Fatalf("CheckUserPassword after reset: %v", err)
	}
}
