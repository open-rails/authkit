package authcore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// #286 account-authority guard against a real store: an operator holding every
// intrinsic root:users:* perm still cannot ban, hard-delete or session-revoke
// the root owner; an empty actor fails closed; peers and the owner's own reach
// are unaffected.
func TestAccountAuthority_NoEscalation_DB(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()

	gs, err := BuildSchema(IntrinsicRootPersona(RoleDef{Name: "operator", Permissions: IntrinsicRootPermissions()}))
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	svc := mustNewService(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	svc.groupSchema = gs
	if _, err := svc.EnsureRootGroup(ctx); err != nil {
		t.Fatalf("ensure root group: %v", err)
	}

	suffix := time.Now().UnixNano()
	mk := func(tag string) string {
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO profiles.users (username) VALUES ($1) RETURNING id::text`, fmt.Sprintf("acctauth-%s-%d", tag, suffix)).Scan(&id); err != nil {
			t.Fatalf("create user %s: %v", tag, err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
		return id
	}
	owner, operator, peer, member := mk("owner"), mk("operator"), mk("peer"), mk("member")
	for id, role := range map[string]string{owner: OwnerRoleName, operator: "operator", peer: "operator"} {
		if err := svc.AssignGroupRoleGenesis(ctx, RootPersona, "", id, SubjectKindUser, role); err != nil {
			t.Fatalf("seed %s: %v", role, err)
		}
	}

	if err := svc.BanUser(ctx, owner, nil, nil, operator); !errors.Is(err, ErrAccountAuthorityEscalation) {
		t.Fatalf("operator ban owner: want ErrAccountAuthorityEscalation, got %v", err)
	}
	if err := svc.HardDeleteUserAs(ctx, operator, owner); !errors.Is(err, ErrAccountAuthorityEscalation) {
		t.Fatalf("operator hard-delete owner: want ErrAccountAuthorityEscalation, got %v", err)
	}
	if err := svc.SoftDeleteUserAs(ctx, operator, owner); !errors.Is(err, ErrAccountAuthorityEscalation) {
		t.Fatalf("operator soft-delete owner: want ErrAccountAuthorityEscalation, got %v", err)
	}
	if err := svc.AdminRevokeUserSessionsAs(ctx, operator, owner); !errors.Is(err, ErrAccountAuthorityEscalation) {
		t.Fatalf("operator revoke owner sessions: want ErrAccountAuthorityEscalation, got %v", err)
	}
	if err := svc.BanUser(ctx, member, nil, nil, ""); !errors.Is(err, ErrInsufficientRoleAuthority) {
		t.Fatalf("empty actor must fail closed, got %v", err)
	}
	u, err := svc.getUserByID(ctx, owner)
	if err != nil || u.BannedAt != nil || u.DeletedAt != nil {
		t.Fatalf("owner must be untouched: err=%v banned=%v deleted=%v", err, u.BannedAt, u.DeletedAt)
	}

	if err := svc.BanUser(ctx, peer, nil, nil, operator); err != nil {
		t.Fatalf("operator ban peer (equal grants): %v", err)
	}
	if err := svc.BanUser(ctx, member, nil, nil, operator); err != nil {
		t.Fatalf("operator ban member: %v", err)
	}
	if err := svc.HardDeleteUserAs(ctx, owner, operator); err != nil {
		t.Fatalf("owner hard-delete operator: %v", err)
	}
	if _, err := svc.getUserByID(ctx, operator); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("operator should be gone, got %v", err)
	}
}
