package authkit_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	pgmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/migratekit"
	"github.com/stretchr/testify/require"
)

func TestTenantMigrationRequiresExplicitLegacyOwnerAndPreservesCredentials(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	ctx := t.Context()
	all, err := migratekit.LoadFromFS(pgmigrations.FS)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(all[len(all)-1].Name, "0018_"))
	m, err := migratekit.NewPostgresFromPGXPool(pg.Pool, "authkit")
	require.NoError(t, err)
	require.NoError(t, m.WithSchema("profiles").ApplyMigrations(ctx, all[:len(all)-1]))
	require.NoError(t, m.Close())
	owner := iam.NewTenantID()
	userID, factorID := uuid.NewString(), uuid.NewString()
	_, err = pg.Pool.Exec(ctx, `INSERT INTO users(id,username,email,email_verified) VALUES($1,'legacy','legacy@example.test',true)`, userID)
	require.NoError(t, err)
	_, err = pg.Pool.Exec(ctx, `INSERT INTO user_passwords(user_id,password_hash) VALUES($1,'fixture-preserved-hash')`, userID)
	require.NoError(t, err)
	secret := []byte("fixture-encrypted-totp-material")
	_, err = pg.Pool.Exec(ctx, `INSERT INTO mfa_factors(id,user_id,method,totp_secret,is_default) VALUES($1,$2,'totp',$3,true)`, factorID, userID, secret)
	require.NoError(t, err)
	_, err = pg.Pool.Exec(ctx, `INSERT INTO permission_groups(id,persona) VALUES($1,'contentkit-tenant')`, owner.String())
	require.NoError(t, err)
	_, err = pg.Pool.Exec(ctx, `INSERT INTO ephemeral_kv(key,value,expires_at) VALUES('password_reset:token:fixture',$1,now()+interval '1 hour')`, []byte("fixture-proof"))
	require.NoError(t, err)
	database := authkit.DatabaseConfig{Schema: "profiles", RiverSchema: "tenant_jobs"}
	err = authkit.Migrate(ctx, pg.Pool, database)
	require.ErrorContains(t, err, "explicit LegacyTenantID")
	var introduced bool
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='profiles' AND table_name='users' AND column_name='tenant_id')`).Scan(&introduced))
	require.False(t, introduced, "a refused adoption must roll back its DDL")
	require.NoError(t, authkit.Migrate(ctx, pg.Pool, database, authkit.MigrationOptions{LegacyTenantID: owner}))
	var storedTenant, storedPassword, groupPersona string
	var storedSecret []byte
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT tenant_id::text FROM users WHERE id=$1`, userID).Scan(&storedTenant))
	require.Equal(t, owner.String(), storedTenant)
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT password_hash FROM user_passwords WHERE user_id=$1`, userID).Scan(&storedPassword))
	require.Equal(t, "fixture-preserved-hash", storedPassword)
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT totp_secret FROM mfa_factors WHERE id=$1 AND user_id=$2`, factorID, userID).Scan(&storedSecret))
	require.Equal(t, secret, storedSecret)
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT persona FROM permission_groups WHERE id=$1 AND tenant_id=$1`, owner.String()).Scan(&groupPersona))
	require.Equal(t, "contentkit-tenant", groupPersona, "persona and grants await explicit migration")
	var proof []byte
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT value FROM ephemeral_kv WHERE key=$1`, "tenant:"+owner.String()+":password_reset:token:fixture").Scan(&proof))
	require.Equal(t, []byte("fixture-proof"), proof)

	other := iam.NewTenantID()
	_, err = pg.Pool.Exec(ctx, `INSERT INTO tenants(id) VALUES($1)`, other.String())
	require.NoError(t, err)
	_, err = pg.Pool.Exec(ctx, `INSERT INTO name_claims(tenant_id,name,owner_id,canonical) VALUES($1,'foreign', $2, true)`, other.String(), userID)
	require.Error(t, err, "a name cannot claim a different tenant's account")
	_, err = pg.Pool.Exec(ctx, `INSERT INTO name_claims(tenant_id,name,owner_id,canonical) VALUES($1,'orphan',$2,true)`, owner.String(), uuid.NewString())
	require.Error(t, err, "canonical names require a real owner by commit")
	_, err = pg.Pool.Exec(ctx, `INSERT INTO name_claims(tenant_id,name,owner_id,canonical) VALUES($1,'retired',$2,false)`, owner.String(), uuid.NewString())
	require.NoError(t, err, "permanent purged-name reservations remain valid")
}
