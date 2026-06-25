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
		// Email-bound tests insert fixed @example.com addresses; clear them so a
		// re-run doesn't collide on users_email_uidx.
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email LIKE '%@example.com'`)
	}
	clean()
	t.Cleanup(clean)

	gs, err := BuildSchema(
		PersonaDef{
			Name: "org", AllowedParents: []string{RootPersona},
			Routes: ManagementProfile{MemberAssignment: true, InviteLinks: true},
			Roles:  []RoleDef{{Name: "member", Permissions: []string{"org:repo:read"}}},
		},
	)
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	svc := NewService(Options{Issuer: "https://test", NativeUserRegistrationMode: mode}, Keyset{}, WithPostgres(pool))
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

	// Idempotent: second redeem succeeds and does NOT increment uses.
	if _, err := svc.RedeemGroupInviteLink(ctx, created.Code, user); err != nil {
		t.Fatalf("idempotent redeem: %v", err)
	}
	if uses := usesOf(t, pool, created.ID); uses != 1 {
		t.Fatalf("idempotent re-redeem burned a use: uses=%d, want 1", uses)
	}
}

// TestInviteLink_EmailBound: an email-bound link redeems only for the matching
// VERIFIED address; a mismatched or unverified redeemer is rejected.
func TestInviteLink_EmailBound(t *testing.T) {
	svc, pool, ctx := setupInviteLinkTest(t, RegistrationModeOpen)
	inviter := acmeOwner(t, svc, ctx, pool)
	bob := insertUserWithEmail(t, pool, "bob@example.com", true)
	mallory := insertUserWithEmail(t, pool, "mallory@example.com", true)
	unverified := insertUserWithEmail(t, pool, "eve@example.com", false)

	mint := func(email string) GroupInviteLinkCreated {
		c, err := svc.CreateGroupInviteLink(ctx, CreateGroupInviteLinkRequest{
			Persona: "org", InstanceSlug: "acme", Role: "member", Email: email, InvitedBy: inviter,
		})
		if err != nil {
			t.Fatalf("mint for %s: %v", email, err)
		}
		return c
	}

	// Matching verified email: success.
	if _, err := svc.RedeemGroupInviteLink(ctx, mint("bob@example.com").Code, bob); err != nil {
		t.Fatalf("bob redeem own invite: %v", err)
	}
	mustHoldMember(t, svc, ctx, bob)

	// Wrong user (different verified email): rejected.
	if _, err := svc.RedeemGroupInviteLink(ctx, mint("carol@example.com").Code, mallory); !errors.Is(err, ErrInviteEmailMismatch) {
		t.Fatalf("mismatched redeemer = %v, want ErrInviteEmailMismatch", err)
	}
	// Right address but UNVERIFIED: rejected.
	if _, err := svc.RedeemGroupInviteLink(ctx, mint("eve@example.com").Code, unverified); !errors.Is(err, ErrInviteEmailMismatch) {
		t.Fatalf("unverified redeemer = %v, want ErrInviteEmailMismatch", err)
	}
}

// TestInviteLink_ExpiryRevokeExhausted covers the three "link no longer usable"
// refusals.
func TestInviteLink_ExpiryRevokeExhausted(t *testing.T) {
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

	// Exhausted: max_uses = 1, first redeem ok, second refused.
	one := 1
	capped, _ := svc.CreateGroupInviteLink(ctx, CreateGroupInviteLinkRequest{Persona: "org", InstanceSlug: "acme", Role: "member", MaxUses: &one, InvitedBy: inviter})
	if _, err := svc.RedeemGroupInviteLink(ctx, capped.Code, insertBareUser(t, pool)); err != nil {
		t.Fatalf("first capped redeem: %v", err)
	}
	if _, err := svc.RedeemGroupInviteLink(ctx, capped.Code, insertBareUser(t, pool)); !errors.Is(err, ErrInviteLinkExhausted) {
		t.Fatalf("second capped redeem = %v, want ErrInviteLinkExhausted", err)
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
		Name: "org", AllowedParents: []string{RootPersona},
		Routes: ManagementProfile{MemberAssignment: true, InviteLinks: true},
		Roles: []RoleDef{
			{Name: "member", Permissions: []string{"org:repo:read"}},
			{Name: "member-manager", Permissions: []string{PermMembersManage("org"), "org:repo:read"}},
		},
	})
	if err != nil {
		t.Fatalf("BuildSchema: %v", err)
	}
	svc := NewService(Options{Issuer: "https://test", NativeUserRegistrationMode: RegistrationModeOpen}, Keyset{}, WithPostgres(pool))
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

func usesOf(t *testing.T, pool *pgxpool.Pool, linkID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT uses FROM profiles.group_invite_links WHERE id = $1::uuid`, linkID).Scan(&n); err != nil {
		t.Fatalf("read uses: %v", err)
	}
	return n
}
