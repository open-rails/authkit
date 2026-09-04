package authcore

import (
	"context"
	"errors"
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
)

// #326: every user-identifier write surfaces a unique violation as the typed
// conflict its flow already speaks, never a raw 23505.
func TestUserIdentifierWritesMapUniqueViolations(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pg.Pool))

	first, err := svc.CreateUser(ctx, "first@example.com", "dupname")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateUser(ctx, "second@example.com", "dupname"); !errors.Is(err, ErrUsernameInUse) {
		t.Fatalf("duplicate username err=%v, want ErrUsernameInUse", err)
	}
	if _, err := svc.CreateUser(ctx, "first@example.com", "othername"); !errors.Is(err, ErrEmailInUse) {
		t.Fatalf("duplicate email err=%v, want ErrEmailInUse", err)
	}
	if _, err := svc.createEmailRegistrationUser(ctx, "first@example.com", "reguser", "hash", true); !errors.Is(err, ErrEmailInUse) {
		t.Fatalf("registration duplicate email err=%v, want ErrEmailInUse", err)
	}
	if _, err := svc.createEmailRegistrationUser(ctx, "third@example.com", "dupname", "hash", true); !errors.Is(err, ErrUsernameInUse) {
		t.Fatalf("registration duplicate username err=%v, want ErrUsernameInUse", err)
	}

	if _, err := svc.createPhoneRegistrationUser(ctx, "+15550000001", "phoneone", "hash", true); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.createPhoneRegistrationUser(ctx, "+15550000001", "phonetwo", "hash", true); !errors.Is(err, ErrPhoneInUse) {
		t.Fatalf("duplicate phone err=%v, want ErrPhoneInUse", err)
	}

	other, err := svc.CreateUser(ctx, "other@example.com", "renamer")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateEmail(ctx, other.ID, "first@example.com"); !errors.Is(err, ErrEmailInUse) {
		t.Fatalf("UpdateEmail onto a taken email err=%v, want ErrEmailInUse", err)
	}
	_ = first
}
