package authcore

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupInviteLinkTest builds a Service with invite links ENABLED (open
// registration) over a real DB, a one-persona schema ("org" with a non-MFA
// "member" role), and a single org group "acme". Returns the service + pool.
func setupInviteLinkTest(t *testing.T, mode RegistrationMode) (*Service, *pgxpool.Pool, context.Context) {
	t.Helper()
	pool := testPG(t)
	ctx := context.Background()
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_invite_links`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_user_roles`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_persona_parents`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email LIKE '%@example.com'`)
	}
	clean()
	t.Cleanup(clean)

	gs, err := BuildSchema(
		PersonaDef{
			Name: "org", Parent: RootPersona,
			Roles: []RoleDef{{Name: "member", Permissions: []string{"org:repo:read"}}},
		},
	)
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	// Verification defaults to Required (secure default), which routes registration
	// through the ephemeral store + an email sender — neither is wired in this DB-only
	// harness. These tests exercise invite/registration flows directly, so pin None:
	// users register immediately, matching the register+join assertions below.
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}, Registration: RegistrationConfig{NativeUserMode: mode, Verification: RegistrationVerificationNone}}, Keyset{}, WithPostgres(pool))
	svc.groupSchema = gs
	if err := svc.SeedPermissionGroupContainment(ctx); err != nil {
		t.Fatalf("SeedPermissionGroupContainment: %v", err)
	}
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme"}); err != nil {
		t.Fatalf("CreatePermissionGroup: %v", err)
	}
	return svc, pool, ctx
}

func insertUserWithEmail(t *testing.T, pool *pgxpool.Pool, email string, verified bool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO profiles.users (email, email_verified) VALUES ($1, $2) RETURNING id::text`,
		email, verified).Scan(&id); err != nil {
		t.Fatalf("insert user %s: %v", email, err)
	}
	return id
}

// acmeOwner creates a fresh user and seeds them as OWNER of the org/acme group via
// the genesis (unchecked) path, so they may legitimately mint invites — the mint
// now enforces no-escalation (AK2-AUTHZ-1), so an unauthorized minter is rejected.
func acmeOwner(t *testing.T, svc *Service, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	id := insertBareUser(t, pool)
	if err := svc.AssignGroupRole(ctx, "org", "acme", id, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("seed acme owner: %v", err)
	}
	return id
}

func mustHoldMember(t *testing.T, svc *Service, ctx context.Context, userID string) {
	t.Helper()
	ok, err := svc.Can(ctx, userID, SubjectKindUser, "org", "acme", "org:repo:read")
	if err != nil || !ok {
		t.Fatalf("user should hold org:repo:read after redeem; got ok=%v err=%v", ok, err)
	}
}

// TestInviteLink_ShareableRedeemIdempotent: a shareable (unbound) link assigns the
// role on redeem; a second redeem by the same user is a no-op (no use burned).
func TestInviteLink_ShareableRedeemIdempotent(t *testing.T) {
	svc, pool, ctx := setupInviteLinkTest(t, RegistrationModeOpen)
	user := insertBareUser(t, pool)

	created, err := svc.CreateGroupInviteLink(ctx, CreateGroupInviteLinkRequest{
		Persona: "org", InstanceSlug: "acme", Role: "member", InvitedBy: acmeOwner(t, svc, ctx, pool),
	})
	if err != nil {
		t.Fatalf("CreateGroupInviteLink: %v", err)
	}
	if created.Code == "" || created.URL == "" {
		t.Fatalf("mint should return a plaintext code + url; got %+v", created)
	}

	res, err := svc.RedeemGroupInviteLink(ctx, created.Code, user)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if res.Persona != "org" || res.InstanceSlug != "acme" || res.Role != "member" {
		t.Fatalf("unexpected redeem result: %+v", res)
	}
	mustHoldMember(t, svc, ctx, user)

	// Idempotent: second redeem succeeds and keeps the link redeemed.
	if _, err := svc.RedeemGroupInviteLink(ctx, created.Code, user); err != nil {
		t.Fatalf("idempotent redeem: %v", err)
	}
	if !isRedeemed(t, pool, created.ID) {
		t.Fatal("idempotent re-redeem cleared redeemed_at")
	}
}

// TestInviteLink_UnboundSingleUse: group invite links are possession-based and
// single-use. Email delivery is not a redemption constraint.
func TestInviteLink_UnboundSingleUse(t *testing.T) {
	svc, pool, ctx := setupInviteLinkTest(t, RegistrationModeOpen)
	inviter := acmeOwner(t, svc, ctx, pool)
	bob := insertUserWithEmail(t, pool, "bob@example.com", true)
	mallory := insertUserWithEmail(t, pool, "mallory@example.com", true)

	created, err := svc.CreateGroupInviteLink(ctx, CreateGroupInviteLinkRequest{
		Persona: "org", InstanceSlug: "acme", Role: "member", InvitedBy: inviter,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := svc.RedeemGroupInviteLink(ctx, created.Code, bob); err != nil {
		t.Fatalf("first holder redeem: %v", err)
	}
	mustHoldMember(t, svc, ctx, bob)

	if _, err := svc.RedeemGroupInviteLink(ctx, created.Code, mallory); !errors.Is(err, ErrInviteLinkNotFound) {
		t.Fatalf("second holder redeem = %v, want ErrInviteLinkNotFound", err)
	}
}

// TestInviteLink_ExpiryRevokeSpent covers "link no longer usable" refusals.
func TestInviteLink_ExpiryRevokeSpent(t *testing.T) {
	svc, pool, ctx := setupInviteLinkTest(t, RegistrationModeOpen)
	inviter := acmeOwner(t, svc, ctx, pool)

	// Expired.
	expired, _ := svc.CreateGroupInviteLink(ctx, CreateGroupInviteLinkRequest{Persona: "org", InstanceSlug: "acme", Role: "member", InvitedBy: inviter})
	if _, err := pool.Exec(ctx, `UPDATE profiles.group_invite_links SET expires_at = now() - interval '1 hour' WHERE id = $1::uuid`, expired.ID); err != nil {
		t.Fatalf("force-expire: %v", err)
	}
	if _, err := svc.RedeemGroupInviteLink(ctx, expired.Code, insertBareUser(t, pool)); !errors.Is(err, ErrInviteLinkExpired) {
		t.Fatalf("expired redeem = %v, want ErrInviteLinkExpired", err)
	}

	// Revoked.
	revoked, _ := svc.CreateGroupInviteLink(ctx, CreateGroupInviteLinkRequest{Persona: "org", InstanceSlug: "acme", Role: "member", InvitedBy: inviter})
	if err := svc.RevokeGroupInviteLink(ctx, "org", "acme", revoked.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.RedeemGroupInviteLink(ctx, revoked.Code, insertBareUser(t, pool)); !errors.Is(err, ErrInviteLinkRevoked) {
		t.Fatalf("revoked redeem = %v, want ErrInviteLinkRevoked", err)
	}

	// Spent: first redeemer gets the role; a different second holder cannot use
	// the same single-use code.
	spent, _ := svc.CreateGroupInviteLink(ctx, CreateGroupInviteLinkRequest{Persona: "org", InstanceSlug: "acme", Role: "member", InvitedBy: inviter})
	if _, err := svc.RedeemGroupInviteLink(ctx, spent.Code, insertBareUser(t, pool)); err != nil {
		t.Fatalf("first single-use redeem: %v", err)
	}
	if _, err := svc.RedeemGroupInviteLink(ctx, spent.Code, insertBareUser(t, pool)); !errors.Is(err, ErrInviteLinkNotFound) {
		t.Fatalf("second single-use redeem = %v, want ErrInviteLinkNotFound", err)
	}
}

// TestInviteLink_GatingDisabled: under a registration mode that forbids invited
// signup, minting an invite link is refused.
func TestInviteLink_GatingDisabled(t *testing.T) {
	svc, pool, ctx := setupInviteLinkTest(t, RegistrationModeClosed)
	_, err := svc.CreateGroupInviteLink(ctx, CreateGroupInviteLinkRequest{
		Persona: "org", InstanceSlug: "acme", Role: "member", InvitedBy: insertBareUser(t, pool),
	})
	if !errors.Is(err, ErrExternalInvitesDisabled) {
		t.Fatalf("mint under closed registration = %v, want ErrExternalInvitesDisabled", err)
	}
	if svc.ExternalInvitesEnabled() {
		t.Fatalf("ExternalInvitesEnabled() should be false under closed registration")
	}
}

// TestInviteLink_MintEnforcesNoEscalation_DB is the AK2-AUTHZ-1 regression: minting
// an invite is a DEFERRED role grant, so the mint must pass the same no-escalation
// check as every other grant surface (#136). A minter with only members:manage
// cannot mint an `owner` invite (which it — or a confederate — could then redeem to
// full owner); an unauthorized user cannot mint at all; an owner can. Mirrors
// TestAssignRoleBySlugAs_NoEscalation_DB on the invite surface.
func TestInviteLink_MintEnforcesNoEscalation_DB(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	clean := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_invite_links`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_user_roles`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.permission_groups`)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_persona_parents`)
	}
	clean()
	t.Cleanup(clean)

	// "org" persona with a bounded `member-manager` (members:manage, NOT owner) and a
	// plain `member`; `owner` (org:*) is auto-injected.
	gs, err := BuildSchema(PersonaDef{
		Name: "org", Parent: RootPersona,
		Roles: []RoleDef{
			{Name: "member", Permissions: []string{"org:repo:read"}},
			{Name: "member-manager", Permissions: []string{PermMembersManage("org"), "org:repo:read"}},
		},
	})
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}, Registration: RegistrationConfig{NativeUserMode: RegistrationModeOpen}}, Keyset{}, WithPostgres(pool))
	svc.groupSchema = gs
	if err := svc.SeedPermissionGroupContainment(ctx); err != nil {
		t.Fatalf("seed containment: %v", err)
	}
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("ensure root group: %v", err)
	}
	if _, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "org", InstanceSlug: "acme"}); err != nil {
		t.Fatalf("create group: %v", err)
	}

	owner := insertBareUser(t, pool)
	if err := svc.AssignGroupRole(ctx, "org", "acme", owner, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	memberMgr := insertBareUser(t, pool)
	if err := svc.AssignGroupRole(ctx, "org", "acme", memberMgr, SubjectKindUser, "member-manager"); err != nil {
		t.Fatalf("seed member-manager: %v", err)
	}
	nobody := insertBareUser(t, pool)

	mint := func(inviter, role string) error {
		_, err := svc.CreateGroupInviteLink(ctx, CreateGroupInviteLinkRequest{
			Persona: "org", InstanceSlug: "acme", Role: role, InvitedBy: inviter,
		})
		return err
	}

	// Unauthorized minter (no members:manage) cannot mint at all.
	if err := mint(nobody, "member"); !errors.Is(err, ErrInsufficientRoleAuthority) {
		t.Fatalf("bare user mint = %v, want ErrInsufficientRoleAuthority", err)
	}
	// member-manager HAS members:manage and covers member's perms → may mint a member invite.
	if err := mint(memberMgr, "member"); err != nil {
		t.Fatalf("member-manager mint member should succeed, got %v", err)
	}
	// THE FIX: member-manager does NOT hold org:* → cannot mint an OWNER invite.
	if err := mint(memberMgr, "owner"); !errors.Is(err, ErrRoleAssignmentEscalation) {
		t.Fatalf("member-manager mint owner = %v, want ErrRoleAssignmentEscalation", err)
	}
	// owner (org:*) covers owner → may mint an owner invite.
	if err := mint(owner, "owner"); err != nil {
		t.Fatalf("owner mint owner should succeed, got %v", err)
	}
}

func isRedeemed(t *testing.T, pool *pgxpool.Pool, linkID string) bool {
	t.Helper()
	var redeemed bool
	if err := pool.QueryRow(context.Background(), `SELECT redeemed_at IS NOT NULL FROM profiles.group_invite_links WHERE id = $1::uuid`, linkID).Scan(&redeemed); err != nil {
		t.Fatalf("read redeemed_at: %v", err)
	}
	return redeemed
}
