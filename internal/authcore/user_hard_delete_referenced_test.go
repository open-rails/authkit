package authcore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
)

// #304: a host table referencing profiles.users(id) WITHOUT ON DELETE CASCADE
// must abort the hard delete as one unit — typed ErrUserReferenced, user row,
// group roles and sessions all intact — and succeed once the reference is gone.
func TestAdminDeleteUserReferencedByHostTable(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	svc := mustNewService(t, Config{Token: TokenConfig{Issuer: "https://test", RefreshTokenDuration: time.Hour}}, Keyset{}, WithPostgres(pool))
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("ensure root group: %v", err)
	}

	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, fmt.Sprintf("hostref-%d", time.Now().UnixNano())).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
	if err := svc.AssignGroupRoleGenesis(ctx, RootPersona, "", id, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if _, _, _, err := svc.insertRefreshSession(ctx, id, "test", net.ParseIP("127.0.0.1"), []string{"pwd"}); err != nil {
		t.Fatalf("issue session: %v", err)
	}

	table := fmt.Sprintf("public.ak304_host_%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, `CREATE TABLE `+table+` (user_id uuid NOT NULL REFERENCES profiles.users(id))`); err != nil {
		t.Fatalf("create host table: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS `+table) })
	if _, err := pool.Exec(ctx, `INSERT INTO `+table+` VALUES ($1::uuid)`, id); err != nil {
		t.Fatalf("reference user: %v", err)
	}

	if err := svc.AdminDeleteUser(ctx, id); !errors.Is(err, ErrUserReferenced) {
		t.Fatalf("want ErrUserReferenced, got %v", err)
	}
	var users, roles int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM profiles.users WHERE id=$1::uuid`, id).Scan(&users); err != nil || users != 1 {
		t.Fatalf("user row must survive a refused delete: n=%d err=%v", users, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM profiles.group_user_roles WHERE user_id=$1::uuid AND deleted_at IS NULL`, id).Scan(&roles); err != nil || roles != 1 {
		t.Fatalf("group roles must survive a refused delete: n=%d err=%v", roles, err)
	}
	sessions, err := svc.ListUserSessions(ctx, id)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("session revoke must roll back with the delete: n=%d err=%v", len(sessions), err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM `+table); err != nil {
		t.Fatalf("drop reference: %v", err)
	}
	if err := svc.AdminDeleteUser(ctx, id); err != nil {
		t.Fatalf("delete after reference removed: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM profiles.users WHERE id=$1::uuid`, id).Scan(&users); err != nil || users != 0 {
		t.Fatalf("user row should be gone: n=%d err=%v", users, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM profiles.group_user_roles WHERE user_id=$1::uuid`, id).Scan(&roles); err != nil || roles != 0 {
		t.Fatalf("group roles should cascade: n=%d err=%v", roles, err)
	}
}
