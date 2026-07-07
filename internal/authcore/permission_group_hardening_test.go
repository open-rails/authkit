package authcore

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestGroupUserRoles_IndexRejectsSecondLiveRole is the #247 hard-rule's
// INDEX-LEVEL guarantee: AssignRole (the only writer used at runtime) always
// upserts a single row per (group, subject), but the partial unique index on
// (permission_group_id, user_id) — NOT including role — is the structural
// backstop that makes a second live role for the same subject in the same
// group impossible for ANY writer, including a raw INSERT that bypasses the
// store entirely. Runs against the deployment's existing (singleton) root
// group with a freshly-created, disposable user — no schema/containment setup
// needed, so it can't collide with other tests' fixtures.
func TestGroupUserRoles_IndexRejectsSecondLiveRole(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	gid, err := svc.EnsureRootGroup(ctx)
	if err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}

	var uid string
	if err := pool.QueryRow(ctx, `INSERT INTO profiles.users DEFAULT VALUES RETURNING id::text`).Scan(&uid); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id = $1::uuid`, uid) })

	if _, err := pool.Exec(ctx,
		`INSERT INTO profiles.group_user_roles (permission_group_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'owner')`,
		gid, uid); err != nil {
		t.Fatalf("first live role insert: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_user_roles WHERE permission_group_id = $1::uuid AND user_id = $2::uuid`, gid, uid)
	})

	// A SECOND live role for the SAME (group, subject) — bypassing AssignRole
	// entirely — must be rejected by the index, not merely by application
	// convention.
	_, err = pool.Exec(ctx,
		`INSERT INTO profiles.group_user_roles (permission_group_id, user_id, role) VALUES ($1::uuid, $2::uuid, 'member')`,
		gid, uid)
	if err == nil {
		t.Fatal("a second live role for the same (group, subject) must be rejected by the unique index")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("expected a unique_violation (23505), got: %v", err)
	}
}

// TestGroupRemoteApplicationRoles_IndexRejectsSecondLiveRole mirrors the user
// case for the remote_application role table.
func TestGroupRemoteApplicationRoles_IndexRejectsSecondLiveRole(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	gid, err := svc.EnsureRootGroup(ctx)
	if err != nil {
		t.Fatalf("EnsureRootGroup: %v", err)
	}

	var appID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO profiles.remote_applications (slug, permission_group_id, issuer, jwks_uri, mode)
		 VALUES ('idx-hardening-app', $1::uuid, 'https://idx-hardening-app.example', 'https://idx-hardening-app.example/.well-known/jwks.json', 'jwks') RETURNING id::text`,
		gid).Scan(&appID); err != nil {
		t.Fatalf("create remote application: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE id = $1::uuid`, appID) })

	if _, err := pool.Exec(ctx,
		`INSERT INTO profiles.group_remote_application_roles (permission_group_id, remote_application_id, role) VALUES ($1::uuid, $2::uuid, 'owner')`,
		gid, appID); err != nil {
		t.Fatalf("first live role insert: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.group_remote_application_roles WHERE permission_group_id = $1::uuid AND remote_application_id = $2::uuid`, gid, appID)
	})

	_, err = pool.Exec(ctx,
		`INSERT INTO profiles.group_remote_application_roles (permission_group_id, remote_application_id, role) VALUES ($1::uuid, $2::uuid, 'member')`,
		gid, appID)
	if err == nil {
		t.Fatal("a second live role for the same (group, remote_application) must be rejected by the unique index")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("expected a unique_violation (23505), got: %v", err)
	}
}
