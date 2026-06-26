package authcore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/open-rails/authkit/password"
)

func TestAccountRegistrationInvite_AllowsInviteOnlyRegistration(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{
		Issuer:                     "https://test",
		NativeUserRegistrationMode: RegistrationModeInviteOnly,
		RegistrationVerification:   RegistrationVerificationNone,
	}, Keyset{}, WithPostgres(pool))
	rootID, err := svc.EnsureRootGroup(ctx)
	if err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}
	inviter := insertBareUser(t, pool)
	if err := NewPermissionGroupStore(pool).AssignRole(ctx, rootID, inviter, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("seed root owner: %v", err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1e10)
	email := "new-" + suffix + "@example.com"
	username := "new" + suffix
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid OR email=$2`, inviter, email)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.account_registration_invites WHERE email=$1`, email)
	})

	if _, err := svc.CreatePendingRegistration(ctx, email, username, "argon2id$hash", 0); !errors.Is(err, ErrRegistrationDisabled) {
		t.Fatalf("registration without invite = %v, want ErrRegistrationDisabled", err)
	}

	created, err := svc.CreateAccountRegistrationInvite(ctx, CreateAccountRegistrationInviteRequest{
		Email:     email,
		InvitedBy: inviter,
	})
	if err != nil {
		t.Fatalf("CreateAccountRegistrationInvite: %v", err)
	}

	wrongCtx := contextWithAccountRegistrationInviteToken(ctx, "wrong")
	if _, err := svc.CreatePendingRegistration(wrongCtx, email, username, "argon2id$hash", 0); !errors.Is(err, ErrRegistrationDisabled) {
		t.Fatalf("registration with wrong invite = %v, want ErrRegistrationDisabled", err)
	}

	phc, err := password.HashArgon2id("secret-pass")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	inviteCtx := contextWithAccountRegistrationInviteToken(ctx, created.Code)
	if _, err := svc.CreatePendingRegistration(inviteCtx, email, username, phc, 0); err != nil {
		t.Fatalf("registration with invite: %v", err)
	}
	u, err := svc.GetUserByEmail(ctx, email)
	if err != nil || u == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if u.Email == nil || *u.Email != email || !u.EmailVerified {
		t.Fatalf("registered user email = %v verified=%v", u.Email, u.EmailVerified)
	}

	var consumed bool
	if err := pool.QueryRow(ctx,
		`SELECT consumed_at IS NOT NULL AND consumed_by = $2::uuid
		   FROM profiles.account_registration_invites WHERE id = $1::uuid`,
		created.ID, u.ID).Scan(&consumed); err != nil {
		t.Fatalf("query invite consumption: %v", err)
	}
	if !consumed {
		t.Fatalf("account registration invite was not consumed by new user")
	}
}
