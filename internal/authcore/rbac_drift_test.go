package authcore

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestRBACDriftReportCountsOrphanedAuthorityRows(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))
	gs, err := BuildSchema(IntrinsicRootPersona(RoleDef{Name: "viewer"}))
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	svc.groupSchema = gs
	rootGID, err := svc.EnsureRootGroup(ctx)
	if err != nil {
		t.Fatalf("ensure root group: %v", err)
	}

	before, err := svc.RBACDriftReport(ctx)
	if err != nil {
		t.Fatalf("RBACDriftReport before: %v", err)
	}
	username := fmt.Sprintf("drift-%d", time.Now().UnixNano())
	role := "retired-" + username
	customRole := "retired-custom-" + username
	var userID string
	if err := pool.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, username).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.api_keys WHERE key_id=$1`, username)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_custom_roles WHERE permission_group_id=$1::uuid AND role=$2`, rootGID, customRole)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_user_roles WHERE permission_group_id=$1::uuid AND user_id=$2::uuid AND role=$3`, rootGID, userID, role)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, userID)
	})

	if _, err := pool.Exec(ctx, `INSERT INTO profiles.group_user_roles (permission_group_id, user_id, role) VALUES ($1::uuid, $2::uuid, $3)`, rootGID, userID, role); err != nil {
		t.Fatalf("insert drift user role: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO profiles.group_custom_roles (permission_group_id, role, permissions) VALUES ($1::uuid, $2, ARRAY['root:users:ban'])`, rootGID, customRole); err != nil {
		t.Fatalf("insert drift custom role: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO profiles.api_keys (permission_group_id, key_id, secret_hash, name, role) VALUES ($1::uuid, $2, decode('00','hex'), 'drift key', $3)`, rootGID, username, role); err != nil {
		t.Fatalf("insert drift api key: %v", err)
	}

	report, err := svc.RBACDriftReport(ctx)
	if err != nil {
		t.Fatalf("RBACDriftReport: %v", err)
	}
	if report.GroupUserRoles-before.GroupUserRoles != 1 || report.CustomRoles-before.CustomRoles != 1 || report.APIKeys-before.APIKeys != 1 || report.Total()-before.Total() != 3 {
		t.Fatalf("report delta = %+v from %+v, want +1/+1/+1 total +3", report, before)
	}
}
