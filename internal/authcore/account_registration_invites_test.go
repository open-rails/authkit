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
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}, Registration: RegistrationConfig{NativeUserMode: RegistrationModeInviteOnly, Verification: RegistrationVerificationNone}}, Keyset{}, WithPostgres(pool))
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

	if _, err := svc.CreatePendingRegistrationWithLanguage(ctx, email, username, "argon2id$hash", 0, ""); !errors.Is(err, ErrRegistrationDisabled) {
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
	if _, err := svc.CreatePendingRegistrationWithLanguage(wrongCtx, email, username, "argon2id$hash", 0, ""); !errors.Is(err, ErrRegistrationDisabled) {
		t.Fatalf("registration with wrong invite = %v, want ErrRegistrationDisabled", err)
	}

	phc, err := password.HashArgon2id("secret-pass")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	inviteCtx := contextWithAccountRegistrationInviteToken(ctx, created.Code)
	if _, err := svc.CreatePendingRegistrationWithLanguage(inviteCtx, email, username, phc, 0, ""); err != nil {
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

// #147 register+join: a role-carrying account-registration invite lets a STRANGER
// register and receive the group role in ONE consume — no separate group invite.
func TestAccountRegistrationInvite_RegisterPlusJoin(t *testing.T) {
	svc, pool, ctx := setupInviteLinkTest(t, RegistrationModeInviteOnly)
	owner := acmeOwner(t, svc, ctx, pool)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1e10)
	email := "joiner-" + suffix + "@example.com"
	username := "joiner" + suffix

	// The org owner mints a role-carrying invite (authorized by org members:manage,
	// NOT root:users:invite).
	created, err := svc.CreateAccountRegistrationInvite(ctx, CreateAccountRegistrationInviteRequest{
		Email:        email,
		InvitedBy:    owner,
		Persona:      "org",
		InstanceSlug: "acme",
		Role:         "member",
	})
	if err != nil {
		t.Fatalf("CreateAccountRegistrationInvite (register+join): %v", err)
	}
	if created.Persona != "org" || created.Role != "member" {
		t.Fatalf("created invite did not echo the carried role: %+v", created)
	}

	phc, err := password.HashArgon2id("secret-pass")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	inviteCtx := contextWithAccountRegistrationInviteToken(ctx, created.Code)
	if _, err := svc.CreatePendingRegistrationWithLanguage(inviteCtx, email, username, phc, 0, ""); err != nil {
		t.Fatalf("register+join registration: %v", err)
	}
	u, err := svc.GetUserByEmail(ctx, email)
	if err != nil || u == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	// The single consume both registered the user AND granted the org/acme role.
	if ok, _ := svc.Can(ctx, u.ID, SubjectKindUser, "org", "acme", "org:repo:read"); !ok {
		t.Fatal("register+join did not grant the carried role on consume")
	}
}

// #147 FINAL: the stranger invite is UNBOUND — a valid single-use code lets the
// holder register under ANY email, not only the address it was delivered to.
func TestAccountRegistrationInvite_UnboundByEmail(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}, Registration: RegistrationConfig{NativeUserMode: RegistrationModeInviteOnly, Verification: RegistrationVerificationNone}}, Keyset{}, WithPostgres(pool))
	rootID, err := svc.EnsureRootGroup(ctx)
	if err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}
	inviter := insertBareUser(t, pool)
	if err := NewPermissionGroupStore(pool).AssignRole(ctx, rootID, inviter, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("seed root owner: %v", err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1e10)
	sentTo := "sent-" + suffix + "@example.com"  // the address AuthKit emailed
	usedBy := "other-" + suffix + "@example.com" // a DIFFERENT address that holds the link
	username := "other" + suffix
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid OR email=ANY($2)`, inviter, []string{sentTo, usedBy})
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.account_registration_invites WHERE email=$1`, sentTo)
	})

	created, err := svc.CreateAccountRegistrationInvite(ctx, CreateAccountRegistrationInviteRequest{
		Email:     sentTo,
		InvitedBy: inviter,
	})
	if err != nil {
		t.Fatalf("CreateAccountRegistrationInvite: %v", err)
	}

	// Register with a DIFFERENT email using the same code — must succeed (unbound).
	phc, err := password.HashArgon2id("secret-pass")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	inviteCtx := contextWithAccountRegistrationInviteToken(ctx, created.Code)
	if _, err := svc.CreatePendingRegistrationWithLanguage(inviteCtx, usedBy, username, phc, 0, ""); err != nil {
		t.Fatalf("unbound registration with a different email: %v", err)
	}
	if u, err := svc.GetUserByEmail(ctx, usedBy); err != nil || u == nil {
		t.Fatalf("different-email user not created: %v", err)
	}

	// The single-use code is now spent — a second registration is rejected.
	if _, err := svc.CreatePendingRegistrationWithLanguage(inviteCtx, "third-"+suffix+"@example.com", "third"+suffix, phc, 0, ""); !errors.Is(err, ErrRegistrationDisabled) {
		t.Fatalf("reuse of a consumed code = %v, want ErrRegistrationDisabled", err)
	}
}
