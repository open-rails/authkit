package core

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// H-4: tenant invites must enforce the no-escalation invariant — the inviter
// must hold every permission the invited role confers — at BOTH invite-create
// time and accept time (the inviter may be demoted in between). Without this, a
// non-owner with tenant:members:manage could invite a confederate as "owner".

// Deterministic, no DB: the check fails closed without a Postgres backend rather
// than silently allowing the grant.
func TestValidateInviteRoleGrant_RequiresPG(t *testing.T) {
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}) // no PG
	if err := svc.ValidateInviteRoleGrant(context.Background(), "t", "user", "owner"); err == nil {
		t.Fatal("expected error without PG")
	}
}

func inviteTestPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestTenantInviteNoEscalation(t *testing.T) {
	pool := inviteTestPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://example.com"}, Keyset{}).WithPostgres(pool)

	const slug = "esc-test-tenant"
	cleanupUser := func(email string) string {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email)
		u, err := svc.CreateUser(ctx, email, email[:len(email)-len("@example.com")])
		if err != nil {
			t.Fatalf("create user %s: %v", email, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })
		return u.ID
	}

	_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug) })

	ownerID := cleanupUser("esc-owner@example.com")
	memberID := cleanupUser("esc-member@example.com")
	inviteeID := cleanupUser("esc-invitee@example.com")

	if _, err := svc.CreateTenant(ctx, slug); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	// owner holds the tenant `owner` role (=`*`); member is a plain member.
	if err := svc.AddMember(ctx, slug, ownerID); err != nil {
		t.Fatalf("add owner member: %v", err)
	}
	if err := svc.AssignRole(ctx, slug, ownerID, "owner"); err != nil {
		t.Fatalf("assign owner: %v", err)
	}
	if err := svc.AddMember(ctx, slug, memberID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := svc.AssignRole(ctx, slug, memberID, "member"); err != nil {
		t.Fatalf("assign member: %v", err)
	}

	t.Run("owner may grant owner", func(t *testing.T) {
		if err := svc.ValidateInviteRoleGrant(ctx, slug, ownerID, "owner"); err != nil {
			t.Fatalf("owner should be able to grant owner: %v", err)
		}
	})

	t.Run("non-owner may not grant owner (invite-time)", func(t *testing.T) {
		// A plain member — and equivalently a member holding only
		// tenant:members:manage — lacks `*`, so it cannot mint an owner invite.
		if err := svc.ValidateInviteRoleGrant(ctx, slug, memberID, "owner"); !errors.Is(err, ErrInviteRoleExceedsGrantor) {
			t.Fatalf("member granting owner: got %v, want ErrInviteRoleExceedsGrantor", err)
		}
	})

	t.Run("accept-time re-check blocks a demoted inviter", func(t *testing.T) {
		// Owner creates a legitimate owner-role invite...
		inv, err := svc.CreateTenantInvite(ctx, slug, inviteeID, ownerID, "owner", nil)
		if err != nil {
			t.Fatalf("create invite: %v", err)
		}
		// ...then the inviter is demoted before the invitee accepts.
		if err := svc.AssignRole(ctx, slug, ownerID, "member"); err != nil {
			t.Fatalf("demote inviter: %v", err)
		}
		// Accept must now be refused — the grantor no longer holds owner authority.
		if err := svc.AcceptTenantInvite(ctx, inv.ID, inviteeID); !errors.Is(err, ErrInviteRoleExceedsGrantor) {
			t.Fatalf("accept after demotion: got %v, want ErrInviteRoleExceedsGrantor", err)
		}
		// And no membership/role was granted to the invitee.
		roles, _ := svc.ReadMemberRoles(ctx, slug, inviteeID)
		for _, r := range roles {
			if r == "owner" {
				t.Fatal("invitee must not have received the owner role")
			}
		}
	})

	t.Run("happy path: owner invites a member and accept succeeds", func(t *testing.T) {
		// Re-promote owner (the previous sub-test demoted them).
		if err := svc.AssignRole(ctx, slug, ownerID, "owner"); err != nil {
			t.Fatalf("re-promote owner: %v", err)
		}
		inv, err := svc.CreateTenantInvite(ctx, slug, inviteeID, ownerID, "member", nil)
		if err != nil {
			t.Fatalf("create member invite: %v", err)
		}
		if err := svc.AcceptTenantInvite(ctx, inv.ID, inviteeID); err != nil {
			t.Fatalf("accept member invite: %v", err)
		}
		roles, err := svc.ReadMemberRoles(ctx, slug, inviteeID)
		if err != nil {
			t.Fatalf("read roles: %v", err)
		}
		found := false
		for _, r := range roles {
			if r == "member" {
				found = true
			}
		}
		if !found {
			t.Fatalf("invitee should hold the member role, got %v", roles)
		}
	})
}
