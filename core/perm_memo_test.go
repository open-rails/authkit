package core

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-rails/authkit/internal/db"
)

// countingDBTX wraps a db.DBTX and counts every statement issued through it. It
// is the spy that proves the #95 memoization contract: a request that checks N
// permissions resolves a layer with exactly ONE query, not N.
type countingDBTX struct {
	inner db.DBTX
	n     int64
}

func (c *countingDBTX) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	atomic.AddInt64(&c.n, 1)
	return c.inner.Exec(ctx, sql, args...)
}

func (c *countingDBTX) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	atomic.AddInt64(&c.n, 1)
	return c.inner.Query(ctx, sql, args...)
}

func (c *countingDBTX) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	atomic.AddInt64(&c.n, 1)
	return c.inner.QueryRow(ctx, sql, args...)
}

func (c *countingDBTX) count() int64 { return atomic.LoadInt64(&c.n) }
func (c *countingDBTX) reset()        { atomic.StoreInt64(&c.n, 0) }

// TestPermissionMemoizationSingleResolution proves the #95 memoization clause:
// within ONE request context, a handler that checks N permissions issues exactly
// ONE resolution query per (layer, principal, org) — and two DIFFERENT requests
// each re-resolve (no cross-request staleness, instant revocation preserved).
// Skips without AUTHKIT_TEST_DATABASE_URL.
func TestPermissionMemoizationSingleResolution(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	suffix := time.Now().UnixNano()

	// A spy DBTX so we can count statements on the hot authz path.
	counter := &countingDBTX{}
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).
		WithPostgres(pool).
		WithDBTXWrapper(func(inner db.DBTX) db.DBTX {
			counter.inner = inner
			return counter
		})

	// --- org fixture: a user who owns an org (owner role grants org:*) ---
	owner, err := svc.CreateUser(ctx, fmt.Sprintf("memo-owner-%d@test.example", suffix), fmt.Sprintf("memoowner%d", suffix))
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, owner.ID) })
	orgSlug := fmt.Sprintf("memo-org-%d", suffix)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, orgSlug) })
	if _, err := svc.CreateOrgForUser(ctx, CreateOrgForUserRequest{Slug: orgSlug, OwnerUserID: owner.ID}); err != nil {
		t.Fatalf("create org for user: %v", err)
	}

	// --- platform fixture: a super-admin (platform:*) ---
	role := fmt.Sprintf("memo-super-%d", suffix)
	t.Cleanup(func() { _, _ = svc.DeletePlatformRole(ctx, role) })
	if err := svc.DefinePlatformRole(ctx, role); err != nil {
		t.Fatalf("define platform role: %v", err)
	}
	if err := svc.SetPlatformRolePermissions(ctx, role, []string{PlatformSuperAdminGrant}); err != nil {
		t.Fatalf("set platform role perms: %v", err)
	}
	if err := svc.AssignPlatformRole(ctx, owner.ID, role); err != nil {
		t.Fatalf("assign platform role: %v", err)
	}
	// regular user: holds NO platform role (must short-circuit to 0 rows).
	plain, err := svc.CreateUser(ctx, fmt.Sprintf("memo-plain-%d@test.example", suffix), fmt.Sprintf("memoplain%d", suffix))
	if err != nil {
		t.Fatalf("create plain: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, plain.ID) })

	// The N distinct perms a busy handler might check in one request.
	orgPerms := []string{
		PermOrgMembersRead, PermOrgMembersCreate, PermOrgMembersUpdate, PermOrgMembersDelete,
		PermOrgRolesRead, PermOrgRolesUpdate, PermOrgAPIKeysRead, PermOrgAPIKeysCreate,
	}
	platformPerms := []string{
		PermPlatformUsersRead, PermPlatformUsersBan, PermPlatformUsersDelete,
		PermPlatformOrgsRead, PermPlatformOrgsUpdate, PermPlatformOrgsRecover,
		PermPlatformMembersCreate, PermPlatformMetricsRead,
	}

	// === ORG layer: N checks in ONE request → exactly ONE query ===
	reqCtx := WithPermissionMemo(ctx)
	counter.reset()
	for _, p := range orgPerms {
		ok, err := svc.HasPermission(reqCtx, orgSlug, owner.ID, p)
		if err != nil {
			t.Fatalf("HasPermission(%s): %v", p, err)
		}
		if !ok {
			t.Fatalf("owner (org:*) should hold %s", p) // allow/deny unchanged
		}
	}
	if got := counter.count(); got != 1 {
		t.Fatalf("org layer: %d checks must issue ONE resolution query, got %d", len(orgPerms), got)
	}

	// === PLATFORM layer: N checks in ONE request → exactly ONE query ===
	reqCtx = WithPermissionMemo(ctx)
	counter.reset()
	for _, p := range platformPerms {
		ok, err := svc.HasPlatformPermission(reqCtx, owner.ID, p)
		if err != nil {
			t.Fatalf("HasPlatformPermission(%s): %v", p, err)
		}
		if !ok {
			t.Fatalf("super-admin (platform:*) should hold %s", p)
		}
	}
	if got := counter.count(); got != 1 {
		t.Fatalf("platform layer: %d checks must issue ONE resolution query, got %d", len(platformPerms), got)
	}

	// === BOTH layers in ONE request → ONE query EACH (2 total) ===
	reqCtx = WithPermissionMemo(ctx)
	counter.reset()
	for _, p := range orgPerms {
		if _, err := svc.HasPermission(reqCtx, orgSlug, owner.ID, p); err != nil {
			t.Fatalf("mixed org check: %v", err)
		}
	}
	for _, p := range platformPerms {
		if _, err := svc.HasPlatformPermission(reqCtx, owner.ID, p); err != nil {
			t.Fatalf("mixed platform check: %v", err)
		}
	}
	if got := counter.count(); got != 2 {
		t.Fatalf("two disjoint layers must resolve once each (2 queries), got %d", got)
	}

	// === regular user with NO platform role: still ONE resolution (0 rows),
	// every subsequent check answered in-memory as deny ===
	reqCtx = WithPermissionMemo(ctx)
	counter.reset()
	for _, p := range platformPerms {
		ok, err := svc.HasPlatformPermission(reqCtx, plain.ID, p)
		if err != nil {
			t.Fatalf("plain HasPlatformPermission(%s): %v", p, err)
		}
		if ok {
			t.Fatalf("regular user must hold NO platform perm, but %s allowed", p)
		}
	}
	if got := counter.count(); got != 1 {
		t.Fatalf("regular user: N denied checks must still be ONE resolution, got %d", got)
	}

	// === two DIFFERENT requests each RE-RESOLVE (no cross-request staleness —
	// instant revocation is a hard #95 requirement) ===
	reqA := WithPermissionMemo(ctx)
	reqB := WithPermissionMemo(ctx)
	counter.reset()
	if _, err := svc.HasPermission(reqA, orgSlug, owner.ID, PermOrgMembersRead); err != nil {
		t.Fatalf("reqA: %v", err)
	}
	if _, err := svc.HasPermission(reqB, orgSlug, owner.ID, PermOrgMembersRead); err != nil {
		t.Fatalf("reqB: %v", err)
	}
	if got := counter.count(); got != 2 {
		t.Fatalf("two distinct request contexts must each re-resolve (2 queries), got %d", got)
	}

	// Sanity: WITHOUT a seeded memo, each check resolves directly (no sharing) —
	// this is the un-memoized fallback for un-seeded internal callers.
	counter.reset()
	for range orgPerms {
		if _, err := svc.HasPermission(ctx, orgSlug, owner.ID, PermOrgMembersRead); err != nil {
			t.Fatalf("unmemoized: %v", err)
		}
	}
	if got := counter.count(); got != int64(len(orgPerms)) {
		t.Fatalf("un-seeded ctx must NOT memoize: expected %d queries, got %d", len(orgPerms), got)
	}
}
