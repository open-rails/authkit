package authkit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	pgmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/migratekit"
	"github.com/stretchr/testify/require"
)

func TestTenantMigrationRetainsDeletedTargetsAndInvitations(t *testing.T) {
	base := testdb.UnlockedPool(t)
	schema := "tenant_receipts_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	pc := base.Config().Copy()
	pc.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{schema}.Sanitize() + ",public"
	pool, err := pgxpool.NewWithConfig(t.Context(), pc)
	require.NoError(t, err)
	t.Cleanup(func() {
		pool.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := base.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		require.NoError(t, err)
		_, err = base.Exec(ctx, "DELETE FROM public.migrations WHERE app='authkit' AND schema=$1", schema)
		require.NoError(t, err)
	})
	all, err := migratekit.LoadFromFS(pgmigrations.FS)
	require.NoError(t, err)
	tenantMigration := 0
	for i, migration := range all {
		if strings.HasPrefix(migration.Name, "0018_") {
			tenantMigration = i
			break
		}
	}
	require.Positive(t, tenantMigration, "tenant migration must remain in the migration chain")
	m, err := migratekit.NewPostgresFromPGXPool(pool, "authkit")
	require.NoError(t, err)
	require.NoError(t, m.WithSchema(schema).ApplyMigrations(t.Context(), all[:tenantMigration]))
	require.NoError(t, m.Close())
	owner := iam.NewTenantID()
	rootID, appID, deletedUser := uuid.NewString(), uuid.NewString(), uuid.NewString()
	_, err = pool.Exec(t.Context(), `INSERT INTO permission_groups(id,persona) VALUES($1,'root'),($2,'legacy')`, rootID, appID)
	require.NoError(t, err)
	_, err = pool.Exec(t.Context(), `INSERT INTO account_deletions(user_id,deleted_at,purge_at,state,purged_at,recipients)
		VALUES($1,now()-interval '31 days',now()-interval '1 day','purged',now()-interval '1 day',ARRAY['https://issuer.test'])`, deletedUser)
	require.NoError(t, err)
	for _, event := range []struct {
		kind, persona    string
		user, group, app *string
	}{
		{kind: "user.purged", user: &deletedUser},
		{kind: "group.purged", persona: "legacy", group: pointer(uuid.NewString())},
		{kind: "role.revoked", persona: "legacy", app: pointer(uuid.NewString())},
		{kind: "group.role_created", persona: "root", group: &rootID},
	} {
		_, err = pool.Exec(t.Context(), `INSERT INTO account_events(issuer,stream,event_id,kind,persona,user_id,group_id,application_id)
			VALUES('https://issuer.test',$1,$2,$1,$3,$4,$5,$6)`, event.kind, uuid.NewString(), event.persona, event.user, event.group, event.app)
		require.NoError(t, err)
	}
	_, err = pool.Exec(t.Context(), `INSERT INTO account_registration_invites(email,permission_group_id,role,code_hash,expires_at)
		VALUES('invite@example.test',$1,'root:reader','preserved-email-proof',now()+interval '1 day')`, rootID)
	require.NoError(t, err)
	_, err = pool.Exec(t.Context(), `INSERT INTO group_invite_links(permission_group_id,role,code_hash)
		VALUES($1,'legacy:reader','preserved-group-proof')`, appID)
	require.NoError(t, err)
	database := authkit.DatabaseConfig{Schema: schema, RiverSchema: schema}
	require.ErrorContains(t, authkit.Migrate(t.Context(), pool, database), "explicit LegacyTenantID")
	require.NoError(t, authkit.Migrate(t.Context(), pool, database, authkit.MigrationOptions{LegacyTenantID: owner}))
	var actual string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT tenant_id::text FROM account_deletions WHERE user_id=$1`, deletedUser).Scan(&actual))
	require.Equal(t, owner.String(), actual)
	var wrong int
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM account_events WHERE persona<>'root' AND tenant_id IS DISTINCT FROM $1::uuid`, owner.String()).Scan(&wrong))
	require.Zero(t, wrong)
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT count(*) FROM account_events WHERE persona='root' AND tenant_id IS NOT NULL`).Scan(&wrong))
	require.Zero(t, wrong)
	for _, table := range []string{"account_registration_invites", "group_invite_links"} {
		require.NoError(t, pool.QueryRow(t.Context(), "SELECT tenant_id::text FROM "+table).Scan(&actual))
		require.Equal(t, owner.String(), actual)
	}
	var proof string
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT code_hash FROM account_registration_invites`).Scan(&proof))
	require.Equal(t, "preserved-email-proof", proof)
	require.NoError(t, pool.QueryRow(t.Context(), `SELECT code_hash FROM group_invite_links`).Scan(&proof))
	require.Equal(t, "preserved-group-proof", proof)
	other := iam.NewTenantID()
	_, err = pool.Exec(t.Context(), `INSERT INTO tenants(id) VALUES($1)`, other.String())
	require.NoError(t, err)
	_, err = pool.Exec(t.Context(), `INSERT INTO group_invite_links(tenant_id,permission_group_id,role,code_hash)
		VALUES($1,$2,'legacy:reader','wrong-owner')`, other.String(), appID)
	require.ErrorContains(t, err, "tenant must match")
	_, err = pool.Exec(t.Context(), `INSERT INTO account_registration_invites(tenant_id,email,permission_group_id,code_hash,expires_at)
		VALUES($1,'plain@example.test',$2,'plain-tenant-invite',now()+interval '1 day')`, owner.String(), owner.String())
	require.NoError(t, err, "a tenant-authorized registration must not grant a role")
	_, err = pool.Exec(t.Context(), `INSERT INTO account_registration_invites(tenant_id,email,permission_group_id,code_hash,expires_at)
		VALUES($1,'bad@example.test',$2,'bad-plain-app-invite',now()+interval '1 day')`, owner.String(), appID)
	require.ErrorContains(t, err, "role-less invitation")
}

func pointer(value string) *string { return &value }
