package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestRecoverOrg exercises the anti-takeover reset (#95): a compromised org with
// an attacker-owner, a member, an api-key, and a remote-app is recovered to the
// rightful owner — locking the bad actors out and restoring control.
// Skips without AUTHKIT_TEST_DATABASE_URL.
func TestRecoverOrg(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)
	suffix := time.Now().UnixNano()

	has := func(xs []string, x string) bool {
		for _, v := range xs {
			if v == x {
				return true
			}
		}
		return false
	}
	mkUser := func(tag string) *User {
		u, err := svc.CreateUser(ctx, fmt.Sprintf("%s-%d@test.example", tag, suffix), fmt.Sprintf("%s%d", tag, suffix))
		if err != nil {
			t.Fatalf("create user %s: %v", tag, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, u.ID) })
		return u
	}

	orgSlug := fmt.Sprintf("hacked-org-%d", suffix)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, orgSlug) })
	org, err := svc.CreateOrg(ctx, orgSlug)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}

	attacker := mkUser("attacker")
	bystander := mkUser("bystander")
	victim := mkUser("victim") // the rightful owner to restore

	// Attacker seized the `owner` role; a bystander is a plain member.
	for _, u := range []*User{attacker, bystander} {
		if err := svc.AddMember(ctx, orgSlug, u.ID); err != nil {
			t.Fatalf("add member: %v", err)
		}
	}
	if err := svc.AssignRole(ctx, orgSlug, attacker.ID, "owner"); err != nil {
		t.Fatalf("assign owner to attacker: %v", err)
	}

	// Plant a (compromised) api-key and remote-app under the org.
	if _, err := pool.Exec(ctx, `INSERT INTO profiles.service_tokens (org_id, key_id, secret_hash, name, role) VALUES ($1,$2,$3,$4,'owner')`,
		org.ID, fmt.Sprintf("key-%d", suffix), "hash", "ci"); err != nil {
		t.Fatalf("insert api-key: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO profiles.remote_applications (slug, issuer, jwks_uri, mode, audiences, enabled, org_id) VALUES ($1,$2,$3,'jwks','{}',true,$4)`,
		fmt.Sprintf("ra-%d", suffix), fmt.Sprintf("https://ra-%d.example", suffix), "https://ra.example/jwks.json", org.ID); err != nil {
		t.Fatalf("insert remote-app: %v", err)
	}

	// --- RECOVER ---
	res, err := svc.RecoverOrg(ctx, org.ID, victim.ID)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if res.APIKeysRevoked != 1 || res.RemoteAppsDisabled != 1 || res.MembersDemoted < 2 {
		t.Fatalf("recover counts unexpected: %+v", res)
	}

	// Victim now holds the owner role → full org authority (org:* expansion).
	vperms, err := svc.EffectivePermissions(ctx, orgSlug, victim.ID)
	if err != nil {
		t.Fatalf("victim perms: %v", err)
	}
	for _, d := range BasePermissions() {
		if !has(vperms, d.Name) {
			t.Fatalf("recovered owner should hold full org authority (missing %s); got %v", d.Name, vperms)
		}
	}

	// Attacker + bystander are demoted → zero authority.
	for _, u := range []*User{attacker, bystander} {
		p, err := svc.EffectivePermissions(ctx, orgSlug, u.ID)
		if err != nil {
			t.Fatalf("demoted perms: %v", err)
		}
		if len(p) != 0 {
			t.Fatalf("demoted member %s must have zero perms, got %v", u.ID, p)
		}
	}

	// Every api-key revoked; every remote-app disabled.
	var liveKeys, liveApps int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM profiles.service_tokens WHERE org_id=$1 AND revoked_at IS NULL`, org.ID).Scan(&liveKeys); err != nil {
		t.Fatalf("count keys: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM profiles.remote_applications WHERE org_id=$1 AND enabled=true`, org.ID).Scan(&liveApps); err != nil {
		t.Fatalf("count apps: %v", err)
	}
	if liveKeys != 0 || liveApps != 0 {
		t.Fatalf("recover left live creds: keys=%d apps=%d", liveKeys, liveApps)
	}
}

func TestRecoverOrgRejectsMissingNewOwnerBeforeMutating(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)
	suffix := time.Now().UnixNano()

	orgSlug := fmt.Sprintf("missing-owner-recover-%d", suffix)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, orgSlug) })
	org, err := svc.CreateOrg(ctx, orgSlug)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	u, err := svc.CreateUser(ctx, fmt.Sprintf("existing-%d@test.example", suffix), fmt.Sprintf("existing%d", suffix))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, u.ID) })
	if err := svc.AddMember(ctx, orgSlug, u.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := svc.AssignRole(ctx, orgSlug, u.ID, "owner"); err != nil {
		t.Fatalf("assign owner: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO profiles.service_tokens (org_id, key_id, secret_hash, name, role) VALUES ($1,$2,$3,$4,'owner')`,
		org.ID, fmt.Sprintf("missing-owner-key-%d", suffix), "hash", "ci"); err != nil {
		t.Fatalf("insert api-key: %v", err)
	}

	_, err = svc.RecoverOrg(ctx, org.ID, "00000000-0000-0000-0000-000000000001")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("recover error = %v, want %v", err, ErrUserNotFound)
	}
	var liveKeys int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM profiles.service_tokens WHERE org_id=$1 AND revoked_at IS NULL`, org.ID).Scan(&liveKeys); err != nil {
		t.Fatalf("count keys: %v", err)
	}
	if liveKeys != 1 {
		t.Fatalf("missing-owner recover mutated org: live keys=%d, want 1", liveKeys)
	}
}
